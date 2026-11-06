#!/usr/bin/env python3
"""WP27 G48 scan — remaining stages closure, LEA-interior unchecked allocs,
skipped-panic adjacency, BSS-global deref report. Summary output only."""
import re, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
img = open("wp3_boot/kernel_raw.bin", "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
SET_LO = 0x9FE51FB0
TEXT_HI = 0x9F780000
ALLOCS = {0x9E82B0E0, 0x9E82B880, 0x9EE30900, 0x9EFF8910, 0x9EFF8B50}

def at(va, n): return img[va - KTEXT: va - KTEXT + n]
def u64(va): return struct.unpack("<Q", at(va, 8))[0] & 0xFFFFFFFF
def u32(va): return struct.unpack("<I", at(va, 4))[0]

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

def disasm_fn(start, cap=0x800):
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

# ---- part 1: caller scans (full text, thunk-aware) ----
print("=== 1. caller scans ===")
def callers_of(target):
    out = []
    for m in re.finditer(rb"[\xe8\xe9]", img[:TEXT_HI - KTEXT]):
        p = m.start()
        rel = struct.unpack("<i", img[p+1:p+5])[0]
        t = KTEXT + p + 5 + rel
        if t == target:
            out.append((KTEXT + p, "direct"))
        elif at(t, 1)[:1] == b"\xe9" and resolve_entry(t) == target:
            out.append((KTEXT + p, "thunk"))
    return out

for tgt in (0x9EC8C9D0, 0x9E7E0650, 0x9E823290, 0x9E9E27F0):
    cs = callers_of(tgt)
    fns = sorted({prologue_back(c) or 0 for c, _ in cs})
    print(f"callers of {tgt:#x}: {len(cs)} sites, fns {[hex(f) for f in fns]}")

# ---- part 2: closure of stages #1290..#1339 ----
print("=== 2. remaining-stage closure ===")
roots = []
for k in range(1290, 1340):
    p = u64(SET_LO + 8 * k)
    if not (0x9FE73EC0 <= p < 0xA0FF9670) or p == 0 or u32(p) < 2: continue
    f = u64(p + 8)
    if f: roots.append((k, resolve_entry(f)))
fn_of_root, visited = {}, set()
queue = [(f, k) for k, f in roots]
while queue:
    f, root = queue.pop(0)
    if f in visited or not (KTEXT <= f < TEXT_HI): continue
    if b"\x55\x48\x89\xe5" not in at(f, 12): continue
    visited.add(f); fn_of_root.setdefault(f, []).append(root)
    for i in disasm_fn(f):
        t = branch_target(i)
        if t is not None and KTEXT <= t < TEXT_HI and t != 0x9F08AA10:
            queue.append((resolve_entry(t), root))
print(f"stages #1290..#1339: {len(roots)} live roots, closure {len(visited)} fns")
for f in (0x9E7E0650, 0x9E823290, 0x9E9E27F0, 0x9EC8C9D0):
    print(f"  {f:#x}: roots {fn_of_root.get(f, '-')}")

# ---- part 3: scan A — unchecked alloc -> interior LEA ----
print("=== 3. scan A: alloc call -> lea R,[rax+K] with NO null check ===")
scan_set = visited | {0x9E7E0650, 0x9E823290, 0x9E9E27F0}
hitsA = []
for f in sorted(scan_set):
    ins = disasm_fn(f)
    for j, i in enumerate(ins):
        t = branch_target(i)
        if t not in ALLOCS or i.mnemonic != "call": continue
        window = ins[j+1:j+7]
        checked = False
        for w in window:
            if w.mnemonic in ("test", "cmp") and "rax" in w.op_str.split(",")[0]:
                checked = True; break
            if w.mnemonic == "lea" and re.match(r"r\w+, \[rax\s*[+-]", w.op_str or ""):
                hitsA.append((f, i.address, w.address, w.op_str))
                break
            if w.mnemonic in ("mov",) and w.op_str.startswith(("rax,", "rbx,", "rcx,", "rdx,", "rsi,", "rdi,")) and w.op_str.endswith("rax"):
                continue  # reg copy — keep scanning window
        # (loop continues; only first lea recorded per alloc site)
print(f"unchecked interior-LEA sites: {len(hitsA)}")
for f, ca, la, ops in hitsA:
    print(f"  fn {f:#x}: alloc@{ca:#x} -> lea@{la:#x} {ops}")

# ---- part 4: skipped panic sites in closure ----
print("=== 4. WP26-skipped panic sites inside closure ===")
rep = open("wp26_g46_report.txt").read()
sk = re.findall(r"0x([0-9a-f]+) fn 0x([0-9a-f]+): (.+)", rep.split("skipped:")[1].split("crossmp global")[0])
inS = [(int(s, 16), int(f, 16), r) for s, f, r in sk if int(f, 16) in scan_set]
print(f"skipped sites whose fn is in the remaining closure: {len(inS)}")
for s, f, r in inS:
    print(f"  site {s:#x} fn {f:#x}: {r}")
