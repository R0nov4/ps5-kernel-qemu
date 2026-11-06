#!/usr/bin/env python3
"""Decode mi_startup (0xffffffff9e9261f0) completely:
- all RIP-relative targets (globals, strings)
- predicate function 0x9eef6b20
- tail call / jmp identity
- exact skip+stamp instruction bytes (for WP2 patching)
- sysinit_set true bounds (from the LEA end marker)
- done-stamp distribution over array order
"""
import sys, struct
sys.path.insert(0, "./scripts")
import wp1_lib as L
import numpy as np

MI = 0xFFFFFFFF9E9261F0

print("=" * 96)
print("MI_STARTUP DECODE — 0xffffffff9e9261f0")
print("=" * 96)

# 1. all rip targets inside mi_startup
print("\n-- 1. RIP-relative targets (globals & strings) --")
seen = {}
for ins in L.disasm(MI, 0x270, maxins=200):
    t = L.rip_target(ins)
    if t is not None:
        key = t
        if key in seen:
            continue
        seen[key] = ins
        s = L.cstr(t, 80)
        val = L.read_u64(t) if L.in_data(t) or (L.TEXT_BASE <= t < L.DATA_BASE) else None
        tag = f"STR: {s!r}" if s else (f"u64: 0x{val:016x}" if val is not None else "")
        # how many qwords around point back into sysinit region?
        print(f"  0x{ins.address:x}  {ins.mnemonic} {ins.op_str:<46s} -> 0x{t:x}  {tag}")

# 2. resolve the two key globals: being_run / set_end
print("\n-- 2. loop-control globals --")
for ins in L.disasm(MI, 0x60, maxins=40):
    t = L.rip_target(ins)
    if t is not None and ins.mnemonic in ("mov", "lea", "cmp"):
        pass  # covered above

# compute the end marker from cold-path lea
ins_cold = [i for i in L.disasm(MI, 0x60, maxins=40)]
for i in ins_cold:
    if i.mnemonic == "lea" and "rax" in i.op_str:
        t = L.rip_target(i)
        if t and t > 0x9FE50000:
            print(f"  cold-path end-marker lea @0x{i.address:x} -> 0x{t:x}")

# 3. predicate function
print("\n-- 3. predicate fn 0xffffffff9eef6b20 (filter call: rdi=0x10, rsi=struct, rdx=0x28) --")
print(L.disasm_str(0xFFFFFFFF9EEF6B20, 0x100, maxins=60))

# 4. tail call + jmp target
print("\n-- 4. tail: call 0x9e8b6fa0(str,0,0,0) then jmp 0x9e92aa50 --")
t_str = 0xFFFFFFFF9E9263B2 + 7 + 0x300255E
print(f"  tail string @0x{t_str:x}: {L.cstr(t_str, 96)!r}")
print("  call target 0x9e8b6fa0 head:")
print(L.disasm_str(0xFFFFFFFF9E8B6FA0, 0x50, maxins=20))
print("  jmp target 0x9e92aa50 head:")
print(L.disasm_str(0xFFFFFFFF9E92AA50, 0x50, maxins=20))

# 5. exact skip + stamp bytes
print("\n-- 5. THE TWO CRITICAL SITES (byte-exact for WP2 patching) --")
for va, name in ((0xFFFFFFFF9E926311, "SKIP-CHECK  cmp dword[sysinit], 2 / jb"),
                 (0xFFFFFFFF9E926331, "THUNK CALL   call rcx (func=+8, udata=+0x10/+0x18)"),
                 (0xFFFFFFFF9E926337, "DONE-STAMP   mov dword[sysinit], 1")):
    b = L.read(va, 16)
    ins = L.disasm(va, 16, maxins=2)
    print(f"  {name}:")
    for k in ins:
        print(f"    0x{k.address:x}  {k.bytes.hex(' '):<20s} {k.mnemonic} {k.op_str}")

# 6. sysinit_set true bounds from lea markers
print("\n-- 6. sysinit_set bounds --")
COLD_LEA = {0xFFFFFFFF9E92622A: "start", None: ""}
for va in (0xFFFFFFFF9E92622A, 0xFFFFFFFF9E926231):
    ins = L.disasm(va, 7, maxins=1)
    if ins:
        t = L.rip_target(ins[0])
        print(f"  lea @0x{va:x} -> 0x{t:x}")
SET_LO = 0xFFFFFFFF9FE51FB0
ins = L.disasm(0xFFFFFFFF9E926231, 7, maxins=1)
SET_HI = L.rip_target(ins[0])
print(f"  => sysinit_set = [0x{SET_LO:x}, 0x{SET_HI:x})  = {SET_HI-SET_LO} bytes = {(SET_HI-SET_LO)//8} qword slots")

# what's between old parse-end 0x9FE55068 and real end?
arr = np.frombuffer(L.data, dtype="<u8")
def q(va):
    return int(arr[(va - L.DATA_BASE) // 8])
print("\n  qwords around old boundary 0x9FE55068 (old end) .. 0x9FE55490 (real end+8):")
for va in range(0xFFFFFFFF9FE55050, 0xFFFFFFFF9FE554A0, 8):
    v = q(va)
    note = ""
    if L.in_text(v) or L.in_data(v):
        s = L.cstr(v, 40)
        if s:
            note = f" -> {s!r}"
    print(f"    0x{va:x}: 0x{v:016x}{note}")

# 7. done-stamp distribution along array order
print("\n-- 7. done-stamp (si_sub) value distribution along ARRAY order --")
vals = []
for k in range((SET_LO - L.DATA_BASE) // 8, (SET_HI - L.DATA_BASE) // 8):
    v = q(L.DATA_BASE + 8 * k)
    if v == 0:
        vals.append(None)   # NULL terminator slot
        continue
    if L.in_data(v) and (v - L.DATA_BASE) % 8 == 0:
        f0 = int(arr[(v - L.DATA_BASE) // 8]) & 0xFFFFFFFF
        vals.append(f0)
    else:
        vals.append(-1)
nonnull = [v for v in vals if v is not None]
print(f"  slots={len(vals)}, non-null structs={len(nonnull)}, NULL slots={vals.count(None)}, other={nonnull.count(-1)}")
from collections import Counter
print(f"  si_sub value histogram: {dict(Counter(v for v in nonnull if v != -1))}")
# where are the zeros? contiguous prefix or scattered?
idx_one = [i for i, v in enumerate(vals) if v == 1]
idx_zero = [i for i, v in enumerate(vals) if v == 0]
if idx_zero:
    print(f"  si_sub==0 (DUMMY, never-run) slots: count={len(idx_zero)}, min={min(idx_zero)}, max={max(idx_zero)}")
    # contiguity check
    runs = []
    s = p = idx_zero[0]
    for i in idx_zero[1:]:
        if i == p + 1:
            p = i
        else:
            runs.append((s, p)); s = p = i
    runs.append((s, p))
    print(f"  zero-runs: {len(runs)} — first 12: {runs[:12]}")
if idx_one:
    print(f"  si_sub==1 (DONE) slots: count={len(idx_one)}, min={min(idx_one)}, max={max(idx_one)}")

# 8. callers of mi_startup
print("\n-- 8. XREFS to mi_startup --")
calls = []
i = 0
while True:
    i = L.text.find(b"\xe8", i)
    if i == -1 or i + 5 > L.TEXT_SIZE:
        break
    rel = struct.unpack_from("<i", L.text, i + 1)[0]
    t = L.TEXT_BASE + i + 5 + rel
    if t == MI and L.in_code(L.TEXT_BASE + i):
        ok, _ = L.aligned_reachable(L.TEXT_BASE + i, maxback=48)
        calls.append((L.TEXT_BASE + i, "call", ok))
    i += 1
# jmp rel32
i = 0
while True:
    i = L.text.find(b"\xe9", i)
    if i == -1 or i + 5 > L.TEXT_SIZE:
        break
    rel = struct.unpack_from("<i", L.text, i + 1)[0]
    t = L.TEXT_BASE + i + 5 + rel
    if t == MI and L.in_code(L.TEXT_BASE + i):
        ok, _ = L.aligned_reachable(L.TEXT_BASE + i, maxback=48)
        calls.append((L.TEXT_BASE + i, "jmp", ok))
    i += 1
for va, kind, ok in calls:
    f, _ = L.containing_function(va)
    print(f"  {kind} 0x{va:x} (aligned={ok}) in func 0x{f:x}")
print(f"  data pointers to mi_startup: {[hex(x) for x in L.data_ptrs_to(MI)]}")
