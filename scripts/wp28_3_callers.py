#!/usr/bin/env python3
"""WP28 part C — callers of stuck fn 0x9f00a3e0, their loops, stage attribution."""
import re, struct
from collections import deque
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT  = 0x9E3F0000
TEXT_HI= 0x9F780000
SET_LO = 0x9FE51FB0
img = open("wp3_boot/kernel_raw.bin", "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
STUCK_FN = 0x9F00A3E0

def at(va, n): return img[va - KTEXT: va - KTEXT + n]
def u64(va): return struct.unpack("<Q", at(va, 8))[0] & 0xFFFFFFFF
def u32(va): return struct.unpack("<I", at(va, 4))[0]
def cstr(va, maxlen=80):
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

print(f"string at 0x9f66e998: {cstr(0x9F66E998)!r}")
print(f"string at 0x9f7334f2: {cstr(0x9F7334F2)!r}")

# tail-stage roots + closure (for attribution)
roots = []
for k in range(1295, 1340):
    p = u64(SET_LO + 8 * k)
    if not (0x9FE73EC0 <= p < 0xA0FF9670) or p == 0 or u32(p) < 2: continue
    f = u64(p + 8)
    if f: roots.append((k, resolve_entry(f)))
fn_of_root, visited = {}, set()
queue = deque((r, k) for k, r in roots)
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
print(f"tail closure: {len(visited)} fns")
print(f"STUCK_FN in closure: {fn_of_root.get(STUCK_FN, 'NOT-IN-TAIL')}")

# all callers of stuck fn (direct + via thunk)
callers = []
for m in re.finditer(rb"[\xe8\xe9]", img[:TEXT_HI - KTEXT]):
    p = m.start()
    rel = struct.unpack("<i", img[p+1:p+5])[0]
    t = KTEXT + p + 5 + rel
    if t == STUCK_FN:
        callers.append((KTEXT + p, "direct"))
    elif KTEXT <= t < TEXT_HI and at(t, 1)[:1] == b"\xe9" and resolve_entry(t) == STUCK_FN:
        callers.append((KTEXT + p, "thunk"))
print(f"\ncallers of {STUCK_FN:#x}: {len(callers)}")
for c, kind in callers:
    cw = prologue_back(c)
    if cw is None:
        print(f"  site {c:#x} ({kind}): NO PROLOGUE (ctx {at(c,8).hex(' ')})")
        continue
    st = fn_of_root.get(cw)
    print(f"  site {c:#x} ({kind}) fn {cw:#x} stages={st if st else 'NOT-IN-TAIL-CLOSURE'}")
    # disasm around the call site to see the enclosing loop
    ins = disasm_fn(cw)
    idx = next((j for j, i in enumerate(ins) if i.address == c), None)
    if idx is None: continue
    # find backward jumps covering the call site
    cover = []
    for i in ins:
        if i.mnemonic.startswith("j") and i.op_str.startswith("0x"):
            t = int(i.op_str, 16)
            if t <= c < i.address and t >= cw: cover.append((i.address, t))
    print(f"      loops covering call: {[(hex(a), hex(t)) for a, t in cover]}")
    for i in ins[max(0, idx-14):idx+4]:
        rt = None
        m2 = re.search(r"rip\s*([+-])\s*(0x[0-9a-f]+)", i.op_str)
        if m2: rt = i.address + i.size + int(m2.group(2), 16) * (-1 if m2.group(1) == "-" else 1)
        note = ""
        if rt and "rip" in i.op_str:
            s = cstr(rt)
            note = f"  ; ->{rt:#x}" + (f" {s!r}" if s else "")
        bt = branch_target(i)
        if bt is not None:
            note += f"  ; {i.mnemonic}->{bt:#x}"
        print(f"      {i.address:#x}: {i.mnemonic} {i.op_str}{note}")
