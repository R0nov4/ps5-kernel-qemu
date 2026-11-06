"""WP1 shared library — PS5 13.60 kernel dump ground-truth access layer.
Layout (SHA-256 verified dump, from repo JSON):
  text: file[0:13,369,344)          @ VA 0xffffffff9e3f0000   (real code from 0xffffffff9e640000)
  data: file[0xcc0000:103,546,880)  @ VA 0xffffffff9f0b0000   (688 zero pages at end)
All addresses below are file offsets OR kernel VAs; helpers convert.
"""
import struct, re, bisect
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DUMP = "./ps5/dump13/kernel-13.60-live.bin"
TEXT_SIZE, DATA_OFF, DATA_SIZE = 13_369_344, 0xCC0000, 90_177_536
TEXT_BASE, DATA_BASE = 0xFFFFFFFF9E3F0000, 0xFFFFFFFF9F0B0000
TEXT_END = TEXT_BASE + TEXT_SIZE            # == DATA_BASE
DATA_END = DATA_BASE + DATA_SIZE
CODE_BASE = 0xFFFFFFFF9E640000              # first byte after the 0xCC padding run

_blob = open(DUMP, "rb").read()
assert len(_blob) == 103_546_880
text = _blob[:TEXT_SIZE]
data = _blob[DATA_OFF:]

md = Cs(CS_ARCH_X86, CS_MODE_64)

# ---------------- VA <-> offset ----------------
def va2off(va):
    if TEXT_BASE <= va < TEXT_END:
        return va - TEXT_BASE
    if DATA_BASE <= va < DATA_END:
        return DATA_OFF + va - DATA_BASE
    return None

def off2va(off):
    if 0 <= off < TEXT_SIZE:
        return TEXT_BASE + off
    if DATA_OFF <= off < DATA_OFF + DATA_SIZE:
        return DATA_BASE + off - DATA_OFF
    return None

def read(va, n):
    off = va2off(va)
    if off is None:
        return b""
    return _blob[off:off + n]

def read_u64(va):
    b = read(va, 8)
    return struct.unpack("<Q", b)[0] if len(b) == 8 else None

def read_u32(va):
    b = read(va, 4)
    return struct.unpack("<I", b)[0] if len(b) == 4 else None

def in_text(va):
    return TEXT_BASE <= va < TEXT_END

def in_code(va):
    return CODE_BASE <= va < TEXT_END

def in_data(va):
    return DATA_BASE <= va < DATA_END

# ---------------- strings ----------------
def cstr(va, maxlen=96):
    """Return printable NUL-terminated string at VA, else None (strict ASCII)."""
    off = va2off(va)
    if off is None or off >= len(_blob):
        return None
    out = bytearray()
    while len(out) < maxlen:
        c = _blob[off + len(out)]
        if c == 0:
            break
        if not (0x20 <= c <= 0x7E):
            return None
        out.append(c)
    return out.decode() if len(out) >= 3 else None

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:/\\-]*$")

def looks_like_name(s):
    return bool(s) and bool(_IDENT_RE.match(s)) and len(s) >= 3

# ---------------- disassembly ----------------
def disasm(va, n=64, maxins=4096):
    """Disassemble n bytes at va; returns list of capstone insns (stops on bad bytes)."""
    off = va2off(va)
    if off is None:
        return []
    out = []
    for ins in md.disasm(_blob[off:off + n], va):
        out.append(ins)
        if len(out) >= maxins:
            break
    return out

def disasm_str(va, n=64, maxins=4096, mark_va=None):
    lines = []
    for ins in disasm(va, n, maxins):
        m = ">>" if mark_va is not None and ins.address == mark_va else "  "
        lines.append(f"{m} 0x{ins.address:x}  {ins.bytes.hex():<22} {ins.mnemonic} {ins.op_str}")
    return "\n".join(lines)

def aligned_reachable(hit_va, maxback=40, maxins=64):
    """True if some instruction stream starting 1..maxback bytes before hit_va
    lands EXACTLY on hit_va (back-sweep verifier; back=0 excluded on purpose).
    Returns (ok, back)."""
    hoff = va2off(hit_va)
    if hoff is None:
        return False, None
    for back in range(1, maxback + 1):
        s = hoff - back
        if s < 0:
            break
        cnt = 0
        for ins in md.disasm(_blob[s:hoff + 16], (off2va(s)), ):
            if ins.address < hit_va and ins.address + ins.size > hit_va:
                break                       # hit falls inside another insn
            if ins.address == hit_va:
                return True, back
            if ins.address > hit_va:
                break
            cnt += 1
            if cnt > maxins:
                break
    return False, None

_RIP_RE = re.compile(r"rip ([+-]) (0x[0-9a-f]+)")

def rip_target(ins):
    """If instruction is RIP-relative, return target VA, else None."""
    m = _RIP_RE.search(ins.op_str)
    if not m:
        return None
    d = int(m.group(2), 16)
    if m.group(1) == "-":
        d = -d
    return ins.address + ins.size + d

# ---------------- function map (from direct CALL rel32 targets) ----------------
_func_starts = None

def function_starts():
    """All call-target function starts in real-code region (cached, sorted)."""
    global _func_starts
    if _func_starts is not None:
        return _func_starts
    starts = set([CODE_BASE])
    for opcode in (0xE8,):
        i = 0
        while True:
            i = text.find(bytes([opcode]), i)
            if i == -1 or i + 5 > TEXT_SIZE:
                break
            if in_code(TEXT_BASE + i):     # only real-code region
                rel = struct.unpack_from("<i", text, i + 1)[0]
                tgt = TEXT_BASE + i + 5 + rel
                if CODE_BASE <= tgt < TEXT_END:
                    starts.add(tgt)
            i += 1
    _func_starts = sorted(starts)
    return _func_starts

def containing_function(va):
    fs = function_starts()
    i = bisect.bisect_right(fs, va) - 1
    if i < 0:
        return None, None
    start = fs[i]
    end = fs[i + 1] if i + 1 < len(fs) else TEXT_END
    return start, min(end, start + 0x4000)   # cap 16KB to bound damage from bad splits

def function_strings(start, end):
    """All printable strings referenced (RIP-relative) inside [start, end)."""
    out = []
    for ins in disasm(start, end - start, maxins=3000):
        t = rip_target(ins)
        if t is not None:
            s = cstr(t)
            if s:
                out.append((ins.address, t, s))
    return out

# ---------------- pointer index into DATA (who points at VA X) ----------------
import numpy as np

_ptr_index = None   # value -> [data offsets]

def _build_ptr_index():
    global _ptr_index
    arr = np.frombuffer(data, dtype="<u8")
    n = len(arr)
    # any qword that is a plausible kernel pointer (text or data VA range)
    m = ((arr >= CODE_BASE) & (arr < TEXT_END)) | ((arr >= DATA_BASE) & (arr < DATA_END))
    idx = np.nonzero(m)[0]
    d = {}
    vals = arr[idx]
    for k in range(len(idx)):
        v = int(vals[k])
        d.setdefault(v, []).append(int(idx[k]))
    _ptr_index = d
    return d

def ptr_index():
    return _ptr_index if _ptr_index is not None else _build_ptr_index()

def data_ptrs_to(va):
    """All data VAs holding a qword == va (empty if none)."""
    d = ptr_index()
    return [DATA_BASE + off for off in d.get(va, [])]

def nearby_name_strings(ptr_va, span=6):
    """For a data location pointing at a function, look at neighboring qwords for
    identifier-like strings (ops tables, kobj method names, sysinit names...)."""
    out = []
    for k in range(-span, span + 1):
        if k == 0:
            continue
        v = read_u64(ptr_va + 8 * k)
        if v is None:
            continue
        s = cstr(v)
        if s and looks_like_name(s):
            out.append((k, s, v))
    return out
