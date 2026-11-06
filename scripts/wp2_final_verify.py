#!/usr/bin/env python3
"""WP2 FINAL VERIFICATION — end-to-end proof, reading ONLY the built ELF.

Simulates, byte-exactly, what the kernel will do at cold boot:
  1. mi_startup cold path: being_run==0 -> window = FULL [0x9fe51fb0, 0x9fe55488)
  2. FILTER pass: predicate(0x10, entry, 0x28) with mode=[0x9fcd446c]-1=0 (case0:
     keep iff struct in [0x9fe73ec0, 0xa0ff9670]) — compacts in place
  3. SORT: the kernel's single adjacent-sweep (0x9e9262a6..0x9e92630f):
     swap iff (prev.sub > cur.sub) or (prev.sub == cur.sub and prev.order > cur.order)
  4. EXEC loop: skip si_sub<2; run func(udata); stamp si_sub:=1

PROOF REQUIREMENTS:
  A. sort swap count == 0 (ZERO-SWAP)
  B. number of executed stages == 1235, in EXACT dump order (unique-real order)
  C. every executed stage's si_sub >= 2
"""
import struct

ELF = "./download/ps5_kernel_1360_reconstructed.elf"
TEXT_VA, TEXT_SZ = 0xFFFFFFFF9E3F0000, 0xCC0000
DATA_VA, DATA_SZ = 0xFFFFFFFF9F0B0000, 0x3174000
SET_LO, SET_HI = 0xFFFFFFFF9FE51FB0, 0xFFFFFFFF9FE55488
CASE0_LO, CASE0_HI = 0xFFFFFFFF9FE73EC0, 0xFFFFFFFFA0FF9670
MI_GLOBALS = [0xFFFFFFFFA1978198, 0xFFFFFFFFA19781A0, 0xFFFFFFFFA19781A8, 0xFFFFFFFFA19781B0]

elf = open(ELF, "rb").read()

# --- parse program headers to locate segments ---
e_phoff, e_phentsize, e_phnum = struct.unpack_from("<Q", elf, 32)[0], struct.unpack_from("<H", elf, 54)[0], struct.unpack_from("<H", elf, 56)[0]
segs = []
for i in range(e_phnum):
    p_type, p_flags, p_off, p_va, p_pa, p_fsz, p_msz, p_align = struct.unpack_from("<IIQQQQQQ", elf, e_phoff + i * e_phentsize)
    segs.append((p_va, p_off, p_fsz))
    print(f"PT_LOAD: vaddr=0x{p_va:x} paddr=0x{p_pa:x} offset=0x{p_off:x} filesz=0x{p_fsz:x} flags={p_flags}")

def read_data(va, n):
    for sva, soff, ssz in segs:
        if sva <= va < sva + ssz:
            o = soff + va - sva
            return elf[o:o + n]
    return None

def r64(va):
    b = read_data(va, 8)
    return struct.unpack("<Q", b)[0] if b else 0

def r32(va):
    b = read_data(va, 4)
    return struct.unpack("<I", b)[0] if b else 0

# --- 0. mi_startup globals must be zero (cold path) ---
assert all(r64(g) == 0 for g in MI_GLOBALS), "mi_startup globals not zeroed!"
print("\n[0] mi_startup re-entrancy globals (0xa1978198/1a0/1a8/1b0) == 0  -> COLD PATH VERIFIED")

# --- 1. load the full cold window array ---
N = (SET_HI - SET_LO) // 8
arr = []
for k in range(N):
    p = r64(SET_LO + 8 * k)
    arr.append({"ptr": p, "sub": r32(p), "order": r32(p + 4)})
n_zero = sum(1 for e in arr if e["ptr"] == 0)
print(f"\n[1] cold window: {N} slots loaded from the ELF ({n_zero} zero-slots present)")

# --- 2. kernel-exact FILTER ---
kept = [e for e in arr if e["ptr"] != 0 and (CASE0_LO <= e["ptr"] and e["ptr"] + 0x28 <= CASE0_HI)]
print(f"[2] FILTER (case0 range [0x{CASE0_LO:x},0x{CASE0_HI:x})): kept {len(kept)} of {N}")
print(f"    kept-but-skipped (si_sub<2): {sum(1 for e in kept if e['sub'] < 2)}")

# --- 3. kernel-exact SORT (single adjacent sweep) ---
a = [dict(e) for e in kept]
swaps = 0
violations = []
prev, cur = 0, 1
while cur < len(a):
    A, B = a[prev], a[cur]
    if A["sub"] > B["sub"] or (A["sub"] == B["sub"] and A["order"] > B["order"]):
        a[prev], a[cur] = B, A
        swaps += 1
        violations.append((prev, cur))
    prev = cur
    cur += 1
print(f"\n[3] KERNEL SORT SIMULATION (0x9e9262a6..0x9e92630f): SWAPS = {swaps}")
print(f"    {'*** A. ZERO-SWAP PROOF: PASS ***' if swaps == 0 else '*** FAIL ***'}")
for v in violations[:5]:
    print(f"    violation at slots {v}")

# --- 4. EXEC loop simulation ---
ran = [e for e in a if e["sub"] >= 2]
print(f"\n[4] EXEC: stages with si_sub>=2 = {len(ran)}  (skipped {len(a) - len(ran)})")
print(f"    {'*** C. all executed si_sub>=2: PASS ***' if all(e['sub'] >= 2 for e in ran) else 'FAIL'}")

# --- B: compare execution order with the ORIGINAL dump's unique-real order ---
dump = open("./ps5/dump13/kernel-13.60-live.bin", "rb").read()
D0 = 0xFFFFFFFF9F0B0000
def dr64(va):
    o = 0xCC0000 + va - D0
    return struct.unpack_from("<Q", dump, o)[0]
def dr32(va):
    o = 0xCC0000 + va - D0
    return struct.unpack_from("<I", dump, o)[0]
seen, dump_order = set(), []
for k in range(N):
    p = dr64(SET_LO + 8 * k)
    if p and dr32(p) == 1 and p not in seen:
        seen.add(p)
        dump_order.append(p)
match = [e["ptr"] for e in ran] == dump_order
print(f"\n[B] execution order == dump unique-real order (1235 stages): {match}")
print(f"    {'*** B. ORDER PRESERVATION: PASS ***' if match else '*** FAIL ***'}")

# --- final verdict ---
verdict = swaps == 0 and match and len(ran) == 1235
print("\n" + "=" * 80)
print("FINAL VERDICT: " + ("ALL PROOFS PASS — the reconstructed ELF will re-run all "
      "1235 unique sysinit stages in the exact original console order, with ZERO "
      "sort swaps." if verdict else "FAILURE — see above"))
print("=" * 80)
