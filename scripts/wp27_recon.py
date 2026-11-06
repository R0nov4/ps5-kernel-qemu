#!/usr/bin/env python3
"""WP27 recon — G47 crash 0x9ec8c9df (CR2=0x90 WRITE, rsi=0x50):
fn disasm, caller hunt, sysinit stage attribution, remaining stages."""
import re, struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"
img = open(IMG, "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
CRASH_FN = 0x9EC8C9D0
SET_LO, SET_HI = 0x9FE51FB0, 0x9FE55488
TEXT_HI = 0x9F780000

def at(va, n): return img[va - KTEXT: va - KTEXT + n]
def u64(va): return struct.unpack("<Q", at(va, 8))[0] & 0xFFFFFFFF
def u32(va): return struct.unpack("<I", at(va, 4))[0]

def cstr(va, maxlen=48):
    out = bytearray(); off = va - KTEXT
    while len(out) < maxlen and 0 <= off < len(img):
        c = img[off + len(out)]
        if c == 0: break
        out.append(c)
    try: s = out.decode("ascii")
    except UnicodeDecodeError: return "<bin>"
    return s if s and all(32 <= ord(ch) < 127 for ch in s) else "<bin>"

def rip_target(i):
    m = re.search(r"rip\s*([+-])\s*(0x[0-9a-f]+)", i.op_str)
    if m:
        return i.address + i.size + int(m.group(2), 16) * (-1 if m.group(1) == "-" else 1)
    return None

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

def resolve_entry(f, hops=4):
    seen = set()
    while hops > 0 and f not in seen:
        seen.add(f); b = at(f, 5)
        if b[0:1] == b"\xe9":
            t = f + 5 + struct.unpack("<i", b[1:5])[0]
            if KTEXT <= t < TEXT_HI: f = t; hops -= 1; continue
        break
    return f

print("=== A. fn 0x9ec8c9d0 (full) ===")
ins = disasm_fn(CRASH_FN, 0x200)
for i in ins:
    rt = rip_target(i)
    note = f"   ; -> {cstr(rt)!r}" if rt and i.mnemonic == "lea" else ""
    mark = "  <<< CRASH" if i.address == 0x9EC8C9DF else ""
    print(f"  {i.address:#x}: {i.mnemonic} {i.op_str}{note}{mark}")
print(f"  (end {ins[-1].address:#x} {ins[-1].mnemonic})")

print("=== B. direct callers of 0x9ec8c9d0 ===")
callers = []
for m in re.finditer(rb"[\xe8\xe9]", img[:0xCC0000]):
    p = m.start()
    rel = struct.unpack("<i", img[p+1:p+5])[0]
    if KTEXT + p + 5 + rel == CRASH_FN:
        callers.append(KTEXT + p)
print(f"raw call/jmp sites: {len(callers)}: {[hex(c) for c in callers]}")
for cs in callers:
    W = prologue_back(cs)
    fi = disasm_fn(W)
    idx = next(j for j, i in enumerate(fi) if i.address == cs)
    print(f"--- caller fn {W:#x}, call @ {cs:#x} ---")
    for i in fi[max(0, idx-8):idx+2]:
        rt = rip_target(i)
        note = f"   ; -> {cstr(rt)!r}" if rt and i.mnemonic == "lea" else ""
        print(f"  {i.address:#x}: {i.mnemonic} {i.op_str}{note}")

print("=== C. sysinit stage attribution ===")
roots = []
for k in range(1184, 1340):
    p = u64(SET_LO + 8 * k)
    if not (0x9FE73EC0 <= p < 0xA0FF9670) or p == 0 or u32(p) < 2: continue
    f = u64(p + 8)
    if f: roots.append((k, f))

def branch_target(i):
    if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
        try: return int(i.op_str, 16)
        except ValueError: return None
    return None

fn_of_root, visited = {}, set()
queue = [(resolve_entry(f), k) for k, f in roots]
caller_hits = {}
while queue:
    f, root = queue.pop(0)
    if f in visited or not (KTEXT <= f < TEXT_HI): continue
    if b"\x55\x48\x89\xe5" not in at(f, 12): continue
    visited.add(f); fn_of_root.setdefault(f, []).append(root)
    for i in disasm_fn(f):
        t = branch_target(i)
        if t is not None and KTEXT <= t < TEXT_HI and t != 0x9F08AA10:
            queue.append((resolve_entry(t), root))
print(f"closure: {len(visited)} fns, {len(roots)} roots")
for cs in callers:
    W = prologue_back(cs)
    print(f"caller fn {W:#x} -> stage roots {fn_of_root.get(W, 'NOT-IN-CLOSURE')}")
print(f"crash fn {CRASH_FN:#x} in closure: {fn_of_root.get(CRASH_FN, 'no')}")

print("=== D. remaining stages after tcp_init ===")
for k, f in roots:
    r = resolve_entry(f)
    print(f"  #{k}: handler {f:#x} -> {r:#x}")
