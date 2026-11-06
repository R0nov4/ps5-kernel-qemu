#!/usr/bin/env python3
"""kdis.py — PS5 13.60 kernel disassembler / data reader.

Usage:
  python3 kdis.py dis <va> [n_insns|0xN_bytes]   disassemble
  python3 kdis.py x   <hexbytes>                 hex bytes -> qword(s)
  python3 kdis.py rd  <va> <len>                 dump data bytes
  python3 kdis.py q   <va> [count]               read qwords
  python3 kdis.py d   <va> [count]               read dwords
  python3 kdis.py find <hexstring>               search whole image
  python3 kdis.py findq <qword>                  search qword value
  python3 kdis.py callers <va>                   scan .text for E8/E9 calls
  python3 kdis.py str <va>                       read C string

Sources: live dump (raw residue) and reconstructed ELF (boot image).
Both share the same VA layout:
  text VA 0xffffffff9e3f0000 (file 0x0 in dump; raw img offset 0)
  data VA 0xffffffff9f0b0000 (file 0xCC0000 in dump; raw img offset 0xCC0000)
img offset -> phys = +0x1E3F0000 ; VA -> img offset = -0xffffffff9e3f0000
"""
import sys, struct, re, os

def _locate(name, extra=()):
    """Find <name> automatically: PS5_DUMP-style env var, script dir, cwd,
    subdirs, then the sandbox paths. Override with PS5_DUMP / PS5_ELF."""
    env = {"kernel-13.60-live.bin": "PS5_DUMP",
           "ps5_kernel_1360_reconstructed.elf": "PS5_ELF"}[name]
    v = os.environ.get(env)
    if v and os.path.exists(v):
        return v
    here = os.path.dirname(os.path.abspath(__file__))
    cands = []
    for base in (here, os.getcwd()):
        cands += [os.path.join(base, name),
                  os.path.join(base, "dump13", name),
                  os.path.join(base, "..", name),
                  os.path.join(base, "..", "dump13", name)] + list(extra)
    cands += ["./ps5/dump13/" + name,
              "./download/dump13/" + name]
    for c in cands:
        if os.path.exists(c):
            return c
    return name  # not found: keep the name so the open() error names the file

DUMP = _locate("kernel-13.60-live.bin")
ELF  = _locate("ps5_kernel_1360_reconstructed.elf")  # informational only (not loaded)
KTEXT = 0xffffffff9e3f0000
KDATA = 0xffffffff9f0b0000
DATA_FOFF = 0xCC0000
KERN_PHYS = 0x1E3F0000

import capstone
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

def load():
    with open(DUMP, "rb") as f:
        return f.read()

IMG = load()

def va2off(va):
    va &= 0xffffffffffffffff
    if va >= KTEXT:
        off = va - KTEXT
    else:
        raise ValueError(f"VA below KTEXT: {va:#x}")
    return off

def read(va, n):
    off = va2off(va)
    if off + n > len(IMG):
        raise ValueError(f"read past EOF: va={va:#x}")
    return IMG[off:off+n]

def dis(va, count=40, is_bytes=False):
    n = count if is_bytes else count
    code = read(va, 0x4000)  # window
    out = []
    done = 0
    for ins in md.disasm(code, va):
        line = f"{ins.address:#018x}  {ins.bytes.hex():<24} {ins.mnemonic} {ins.op_str}"
        # annotate rip-relative
        m = re.search(r"\[rip \+ (0x[0-9a-f]+)\]", ins.op_str)
        m2 = re.search(r"\[rip - (0x[0-9a-f]+)\]", ins.op_str)
        if m:
            tgt = ins.address + ins.size + int(m.group(1), 16)
            line += f"   ; -> {tgt:#x}"
        elif m2:
            tgt = ins.address + ins.size - int(m2.group(1), 16)
            line += f"   ; -> {tgt:#x}"
        # annotate direct call/jmp targets
        if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
            line += f"   ; fn"
        out.append(line)
        done += 1
        if (is_bytes and ins.address + ins.size - va >= n) or (not is_bytes and done >= count):
            break
    return "\n".join(out)

def rd(va, n):
    b = read(va, n)
    lines = []
    for i in range(0, len(b), 16):
        chunk = b[i:i+16]
        hexs = " ".join(f"{c:02x}" for c in chunk)
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        lines.append(f"{va+i:#018x}  {hexs:<48} {asc}")
    return "\n".join(lines)

def qwords(va, count):
    b = read(va, count*8)
    return "\n".join(f"[{va+i*8:#x}] = {struct.unpack_from('<Q', b, i*8)[0]:#018x}" for i in range(count))

def dwords(va, count):
    b = read(va, count*4)
    return "\n".join(f"[{va+i*4:#x}] = {struct.unpack_from('<I', b, i*4)[0]:#010x}" for i in range(count))

def find(hexstr):
    pat = bytes.fromhex(hexstr.replace(" ", ""))
    res = []
    start = 0
    while True:
        i = IMG.find(pat, start)
        if i < 0: break
        va = KTEXT + i
        res.append(f"img {i:#010x}  phys {i+KERN_PHYS:#010x}  va {va:#018x}")
        start = i + 1
        if len(res) > 40: break
    return "\n".join(res) if res else "NOT FOUND"

def callers(va):
    """scan text for E8/E9 rel32 targeting va"""
    tgt = va & 0xffffffff
    res = []
    text = IMG[:DATA_FOFF]
    for i in range(len(text)-5):
        op = text[i]
        if op in (0xE8, 0xE9):
            rel = struct.unpack_from("<i", text, i+1)[0]
            site = KTEXT + i
            if (site + 5 + rel) & 0xffffffff == tgt:
                res.append(f"{'call' if op==0xE8 else 'jmp '} @ {site:#x} (phys {i+KERN_PHYS:#x})")
    return "\n".join(res) if res else "no direct E8/E9 callers found"

def cstr(va, maxlen=200):
    b = read(va, maxlen)
    s = b.split(b"\0")[0]
    return s.decode("utf-8", "replace")

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    if cmd == "dis":
        va = int(sys.argv[2], 0)
        cnt = int(sys.argv[3], 0) if len(sys.argv) > 3 else 40
        isbytes = len(sys.argv) > 4 and sys.argv[4] == "bytes"
        print(dis(va, cnt, isbytes))
    elif cmd == "rd":
        print(rd(int(sys.argv[2], 0), int(sys.argv[3], 0)))
    elif cmd == "q":
        print(qwords(int(sys.argv[2], 0), int(sys.argv[3], 0) if len(sys.argv)>3 else 8))
    elif cmd == "d":
        print(dwords(int(sys.argv[2], 0), int(sys.argv[3], 0) if len(sys.argv)>3 else 8))
    elif cmd in ("find", "f"):
        print(find(sys.argv[2]))
    elif cmd == "findq":
        v = int(sys.argv[2], 0)
        print(find(struct.pack("<Q", v).hex()))
    elif cmd == "findd":
        v = int(sys.argv[2], 0)
        print(find(struct.pack("<I", v).hex()))
    elif cmd == "callers":
        print(callers(int(sys.argv[2], 0)))
    elif cmd == "str":
        print(repr(cstr(int(sys.argv[2], 0))))
    else:
        print(__doc__)
