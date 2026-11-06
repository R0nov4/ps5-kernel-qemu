#!/usr/bin/env python3
"""WP28 analysis (ZERO QEMU / ZERO GDB — static capstone only)

Base image: the USER-VERIFIED G47-only kernel (md5 175a002c...) =
WP26 a822c626... + G47 guard (0x9e7e0670 -> slot 0x9E413B00).
Boot fact: marches through tcp_init + 2nd lapic calib, then 45s of
SILENCE — never reaches the G41 park (0x9e9263a4).  User GDB snapshot
@12s: rip=0x9f00a425  rsp=0xffffffffa2228900 rbp=...8910 r12=0x9e6590e0
  and $-8,%rax / cmp %rcx,%rax / je 0x9f00a470 / lea -> 0x9f66e998

A. stages #1295..#1339 handler table (resolved, strings, calls, loops)
B. stuck fn at 0x9f00a425: full disasm, loop, globals
C. which tail stage reaches the stuck fn (closure attribution)
"""
import re, struct, sys
from collections import deque
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT  = 0x9E3F0000
TEXT_HI= 0x9F780000
SET_LO = 0x9FE51FB0
IMG    = "wp3_boot/kernel_raw.bin"
STUCK  = 0x9F00A425
md = Cs(CS_ARCH_X86, CS_MODE_64)
img = open(IMG, "rb").read()

def at(va, n): return img[va - KTEXT: va - KTEXT + n]
def u64(va): return struct.unpack("<Q", at(va, 8))[0] & 0xFFFFFFFF
def u32(va): return struct.unpack("<I", at(va, 4))[0]

def cstr(va, maxlen=64):
    out = bytearray(); off = va - KTEXT
    while len(out) < maxlen and 0 <= off < len(img):
        c = img[off + len(out)]
        if c == 0: break
        out.append(c)
    try: s = out.decode("ascii")
    except UnicodeDecodeError: return None
    return s if s and all(32 <= ord(ch) < 127 for ch in s) else None

def resolve_entry(f, hops=5):
    seen = set()
    while hops > 0 and f not in seen:
        seen.add(f); b = at(f, 5)
        if b[0:1] == b"\xe9":
            t = f + 5 + struct.unpack("<i", b[1:5])[0]
            if KTEXT <= t < TEXT_HI: f = t; hops -= 1; continue
        break
    return f

def padding_run(va, n=8):
    b = at(va, n)
    return len(b) == n and all(c in (0xCC, 0x90) for c in b)

def prologue_back(va):
    lo = max(KTEXT, va - 0x800)
    idx = bytes(img).rfind(b"\x55\x48\x89\xe5", lo - KTEXT, va - KTEXT + 1)
    return KTEXT + idx if idx >= 0 else None

def disasm_fn(start, cap=0x1000):
    out = []
    for i in md.disasm(at(start, cap), start):
        out.append(i)
        if padding_run(i.address + i.size, 8): break
    return out

def branch_target(i):
    if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
        try: return int(i.op_str, 16)
        except ValueError: return None
    return None

def rip_target(i):
    m = re.search(r"rip\s*([+-])\s*(0x[0-9a-f]+)", i.op_str)
    if m: return i.address + i.size + int(m.group(2), 16) * (-1 if m.group(1) == "-" else 1)
    return None

# ---------------- A. tail stage table ----------------
print("=== A. sysinit stages #1295..#1339 ===")
roots = []
for k in range(1295, 1340):
    p = u64(SET_LO + 8 * k)
    if not (0x9FE73EC0 <= p < 0xA0FF9670) or p == 0 or u32(p) < 2:
        print(f"  #{k}: invalid slot p={p:#x}")
        continue
    f = u64(p + 8); arg = u64(p + 16)
    r = resolve_entry(f) if f else 0
    roots.append((k, f, r, arg))
print(f"valid roots: {len(roots)}")

def fn_summary(f):
    """compact handler summary: strings, calls, loops, port io"""
    try: ins = disasm_fn(f)
    except Exception: return "<disasm-fail>"
    strs, calls, loops, ports, waits = [], set(), 0, set(), set()
    for j, i in enumerate(ins):
        rt = rip_target(i)
        if rt is not None and i.mnemonic in ("lea", "mov") and "rip" in i.op_str:
            s = cstr(rt)
            if s and len(s) >= 4: strs.append(s)
        bt = branch_target(i)
        if bt is not None and i.mnemonic == "call" and KTEXT <= bt < TEXT_HI:
            calls.add(bt)
        if i.mnemonic in ("in", "out"): ports.add(f"{i.mnemonic} {i.op_str}")
        if i.mnemonic.startswith("j") and i.op_str.startswith("0x"):
            t = int(i.op_str, 16)
            if t < i.address: loops += 1
    return ins, strs, calls, loops, ports

WAIT_HINTS = ("wait", "sleep", "pause", "delay", "timeout", "retry", "poll",
              "ready", "busy", "hung", "stall", "block")
for k, f, r, arg in roots:
    ins, strs, calls, loops, ports = fn_summary(r)
    waitish = [s for s in strs if any(h in s.lower() for h in WAIT_HINTS)]
    names = (sorted(set(strs))[:6])
    print(f"  #{k}: h={f:#x} -> {r:#x} arg={arg:#x} sz={len(ins)}i loops={loops} "
          f"calls={len(calls)} ports={sorted(ports) if ports else ''}")
    if waitish: print(f"      WAIT-STRINGS: {waitish}")
    if names:   print(f"      strs: {names}")

# ---------------- B. stuck fn ----------------
print("\n=== B. stuck site 0x9f00a425 ===")
W = prologue_back(STUCK)
print(f"prologue_back -> fn {W:#x}")
ins = disasm_fn(W, 0x1400)
# find loops whose body covers STUCK: backward jumps with target <= STUCK < jump addr
cover = []
for i in ins:
    if i.mnemonic.startswith("j") and i.op_str.startswith("0x"):
        t = int(i.op_str, 16)
        if t <= STUCK < i.address: cover.append((i.address, t))
print(f"loops covering stuck site: {[(hex(a), hex(t)) for a, t in cover]}")
for i in ins:
    rt = rip_target(i)
    note = ""
    if rt is not None and "rip" in i.op_str:
        s = cstr(rt)
        note = f"   ; rip->{rt:#x}" + (f" {s!r}" if s else "")
    bt = branch_target(i)
    if bt is not None and i.mnemonic == "call" and KTEXT <= bt < TEXT_HI:
        bt_r = resolve_entry(bt)
        note += f"   ; call->{bt_r:#x}"
    mark = "  <<<< STUCK" if i.address == STUCK else ""
    print(f"  {i.address:#x}: {i.bytes.hex():<20} {i.mnemonic} {i.op_str}{note}{mark}")

# globals near 0x9f66e998 and r12 value
print(f"\nglobal 0x9f66e998 dump:")
gva = 0x9F66E998
for off in range(-0x20, 0x40, 8):
    q = struct.unpack("<Q", at(gva + off, 8))[0]
    print(f"  {gva+off:#x}: {q:#018x}" + (f"  -> {cstr(q & 0xFFFFFFFF)}" if 0x9E3F0000 <= (q & 0xFFFFFFFF) < 0xA1000000 else ""))
print(f"\nr12 candidate 0x9e6590e0 dump:")
r12 = 0x9E6590E0
for off in range(0, 0x40, 8):
    q = struct.unpack("<Q", at(r12 + off, 8))[0]
    s = cstr(q & 0xFFFFFFFF) if 0x9E3F0000 <= (q & 0xFFFFFFFF) < 0xA1000000 else None
    print(f"  {r12+off:#x}: {q:#018x}" + (f"  -> {s!r}" if s else ""))
print(f"bytes at 0x9e6590e0: {at(r12, 16).hex(' ')}")

# ---------------- C. stage attribution of stuck fn ----------------
print("\n=== C. which tail stage reaches the stuck fn ===")
STUCK_FN = W
fn_of_root = {}
visited = set()
queue = deque()
for k, f, r, arg in roots:
    queue.append((r, k))
while queue:
    f, root = queue.popleft()
    if f in visited or not (KTEXT <= f < TEXT_HI): continue
    if b"\x55\x48\x89\xe5" not in at(f, 12): continue
    visited.add(f); fn_of_root.setdefault(f, []).append(root)
    try: fins = disasm_fn(f)
    except Exception: continue
    for i in fins:
        t = branch_target(i)
        if t is not None and KTEXT <= t < TEXT_HI and t != 0x9F08AA10:
            queue.append((resolve_entry(t), root))
print(f"closure size: {len(visited)}")
print(f"STUCK FN {STUCK_FN:#x} attributed to stages: {fn_of_root.get(STUCK_FN, 'NOT-REACHED')}")
# also: who calls the stuck fn directly (full text)
callers = []
for m in re.finditer(rb"[\xe8\xe9]", img[:TEXT_HI - KTEXT]):
    p = m.start()
    rel = struct.unpack("<i", img[p+1:p+5])[0]
    t = KTEXT + p + 5 + rel
    if t == STUCK_FN or (at(t, 1)[:1] == b"\xe9" and resolve_entry(t) == STUCK_FN):
        callers.append(KTEXT + p)
print(f"direct callers of stuck fn: {[hex(c) for c in callers]}")
for c in callers:
    cw = prologue_back(c)
    print(f"  caller site {c:#x} in fn {cw:#x} -> stages {fn_of_root.get(cw, 'NOT-IN-TAIL-CLOSURE')}")
