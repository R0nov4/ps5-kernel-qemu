#!/usr/bin/env python3
"""WP2 STEP 3 (final) — sysinit reconstruction + kernel-exact simulations.

DESIGN (all decisions byte-verified this session):
  * mi_startup cold path: being_run==0 -> window = FULL [0x9fe51fb0, 0x9fe55488)
  * FILTER: predicate(0x10, struct, 0x28), mode = [0x9fcd446c]-1 = 0 -> case0:
    keep iff struct in [0x9fe73ec0, 0xa0ff9670] (live .data range globals)
  * SORT: SINGLE adjacent-swap sweep (0x9e9262a6..30f) — swap iff
    (prev.sub > cur.sub) or (prev.sub == cur.sub and prev.order > cur.order)
  * EXEC: skip si_sub < 2; call func(udata); stamp si_sub := 1
  * DUMP REALITY: 351 of the 1586 DONE slots are compaction-residue DUPLICATES
    -> true unique stage count = 1235; duplicates must be zeroed or they would
    double-execute.
  * RECONSTRUCTED ARRAY:
      [0 .. 104]   105 unique dummy entries, sorted by si_order asc  (si_sub=0)
      [105 .. 1339] 1235 unique real entries in DUMP order (== original linker
                    order, stable across compactions), si_sub := 2,3,4.. groups
      [1340 .. 1690] 351 ZERO slots (predicate(0) -> filtered out safely)
"""
import sys, struct, json
sys.path.insert(0, "./scripts")
import wp1_lib as L
from collections import Counter

SET_LO, SET_HI = 0xFFFFFFFF9FE51FB0, 0xFFFFFFFF9FE55488
CASE0_LO, CASE0_HI = 0xFFFFFFFF9FE73EC0, 0xFFFFFFFFA0FF9670
MULTI = [(0xFFFFFFFF9FE73EC0, 0xFFFFFFFFA0FF9670),
         (0xFFFFFFFF9FE72E90, 0xFFFFFFFF9FE73EB0),
         (0xFFFFFFFF9FE6F8A0, 0xFFFFFFFF9FE72E90),
         (0xFFFFFFFF9FE6D520, 0xFFFFFFFF9FE6F8A0)]

# ---------- extract ----------
slots = []
for k in range((SET_HI - SET_LO) // 8):
    p = L.read_u64(SET_LO + 8 * k)
    slots.append({"slot": k, "ptr": p, "sub": L.read_u32(p),
                  "order": L.read_u32(p + 4), "func": L.read_u64(p + 8)})
dummies = [s for s in slots if s["sub"] == 0]
reals   = [s for s in slots if s["sub"] == 1]

# dedupe reals (keep FIRST occurrence — compaction moved survivors down)
seen = set()
unique_reals, dup_slots = [], []
for s in reals:
    if s["ptr"] in seen:
        dup_slots.append(s["slot"])
    else:
        seen.add(s["ptr"])
        unique_reals.append(s)
print(f"slots=1691  dummies={len(dummies)}  done-slots={len(reals)}  "
      f"unique-real-stages={len(unique_reals)}  duplicate-slots={len(dup_slots)}")

# ---------- case0 filter reach check ----------
out_case0 = [s for s in unique_reals if not (CASE0_LO <= s["ptr"] and s["ptr"] + 0x28 <= CASE0_HI)]
out_multi = [s for s in unique_reals
             if not any(lo <= s["ptr"] and s["ptr"] + 0x28 <= hi for lo, hi in MULTI)]
print(f"unique reals OUTSIDE case0 single-range: {len(out_case0)}")
for s in out_case0[:12]:
    print(f"   slot {s['slot']}: struct 0x{s['ptr']:x} order=0x{s['order']:x} func=0x{s['func']:x}")
print(f"unique reals OUTSIDE multi-range (case5): {len(out_multi)}")

# ---------- group synthesis (on unique reals, dump order) ----------
group = 2
prev_order = None
for s in unique_reals:
    if prev_order is not None and s["order"] < prev_order:
        group += 1
    s["new_sub"] = group
    prev_order = s["order"]
n_groups = group - 1
print(f"group synthesis: {n_groups} synthetic groups (si_sub 2..{group-1})")

# dummies sorted by order
dummies_sorted = sorted(dummies, key=lambda s: (s["order"], s["ptr"]))
for s in dummies_sorted:
    s["new_sub"] = 0

# ---------- final array ----------
final = dummies_sorted + unique_reals
n_zero = 1691 - len(final)
assert n_zero == len(dup_slots), (n_zero, len(dup_slots))

def predicate_case0(ptr):
    return CASE0_LO <= ptr and ptr + 0x28 <= CASE0_HI

# ---------- EXACT kernel simulations ----------
def kernel_filter_sim(arr):
    return [e for e in arr if predicate_case0(e["ptr"])]

def kernel_sort_sim(arr):
    """byte-exact single adjacent sweep @0x9e9262a6..0x9e92630f"""
    a = list(arr)
    swaps = 0
    violated = []
    prev = 0
    cur = 1
    n = len(a)
    while cur < n:
        A, B = a[prev], a[cur]
        if A["new_sub"] > B["new_sub"] or (A["new_sub"] == B["new_sub"] and A["order"] > B["order"]):
            a[prev], a[cur] = B, A
            swaps += 1
            violated.append((prev, cur, A["new_sub"], B["new_sub"], A["order"], B["order"]))
        prev = cur
        cur += 1
    return swaps, violated, a

kept = kernel_filter_sim(final)
swaps, violated, sorted_arr = kernel_sort_sim(kept)
print(f"\n*** KERNEL-EXACT SIMULATION (filter case0 + single-sweep sort) ***")
print(f"  filter: {len(final)} -> {len(kept)} slots "
      f"(kept dummies={sum(1 for e in kept if e['new_sub']==0)}, "
      f"kept reals={sum(1 for e in kept if e['new_sub']>=2)})")
print(f"  SORT SWAPS = {swaps}   {'*** ZERO-SWAP PROOF: PASS ***' if swaps == 0 else 'FAIL'}")
for v in violated[:10]:
    print(f"    violation @({v[0]},{v[1]}): subs {v[2]}->{v[3]} orders 0x{v[4]:x}->0x{v[5]:x}")

# exec simulation
ran = [e for e in sorted_arr if e["new_sub"] >= 2]
dump_order_ptrs = [s["ptr"] for s in unique_reals]
exec_order = [e["ptr"] for e in ran]
print(f"\n*** EXEC SIMULATION ***")
print(f"  executed stages (si_sub>=2): {len(ran)}   skipped: {len(sorted_arr) - len(ran)}")
print(f"  exec order == dump unique-real order: {exec_order == dump_order_ptrs}")

# ---------- also prove: WITHOUT filter (raw array incl. zero slots removed already) ----------
swaps_raw, v_raw, _ = kernel_sort_sim(final)
print(f"\n  (raw array, no filter): swaps = {swaps_raw}  "
      f"{'PASS' if swaps_raw == 0 else 'see violations'}")

# ---------- sysuninit oracle (validation data) ----------
oracle = Counter()
va = SET_HI
while va < 0xFFFFFFFF9FE57A00:
    p = L.read_u64(va)
    if p and L.in_data(p):
        sub = L.read_u32(p)
        f = L.read_u64(p + 8)
        if f and L.in_text(f) and sub != 0:
            oracle[sub] += 1
    va += 8
print(f"\nsysuninit oracle (original SI_SUB enum histogram):")
ENUM = {0x6000000: "SI_SUB_VM", 0x1800000: "SI_SUB_KMEM", 0x1B00000: "SI_SUB_LOCK(?)",
        0x2000000: "SI_SUB_KVM", 0x2160000: "?", 0x3100000: "SI_SUB_RUN_QUEUE(?)",
        0x3810000: "?", 0x7000000: "?", 0x8700000: "?", 0x8800800: "?",
        0xA000000: "SI_SUB_INIT_IF", 0xF000000: "SI_SUB_INTR(?)"}
for sub, c in oracle.most_common(15):
    print(f"   si_sub=0x{sub:x} ({ENUM.get(sub, '?')}): {c} teardown entries")

# ---------- save patch plan ----------
plan = {
  "set_bounds": [hex(SET_LO), hex(SET_HI)], "total_slots": 1691,
  "unique_real_stages": len(unique_reals), "duplicate_slots_zeroed": len(dup_slots),
  "dummy_entries": len(dummies),
  "case0_range": [hex(CASE0_LO), hex(CASE0_HI)],
  "reals_outside_case0": len(out_case0),
  "filter_kept_after_patch": len(kept),
  "groups": n_groups, "sort_swaps": swaps,
  "exec_stages": len(ran), "exec_order_matches_dump": exec_order == dump_order_ptrs,
  "struct_si_sub_patches": [
      {"ptr": hex(s["ptr"]), "slot_first": s["slot"], "si_sub": s["new_sub"],
       "order": s["order"]} for s in unique_reals],
  "array_slots": [
      {"slot": i, "value": hex(s["ptr"]) if s["ptr"] else "0"} for i, s in enumerate(final)],
  "zero_slots_range": [len(final), 1690],
  "sysuninit_oracle": {hex(k): v for k, v in oracle.most_common(30)},
}
with open("./download/ps5_wp2/wp2_3_sysinit_plan.json", "w") as f:
    json.dump(plan, f, indent=1)
print("\nsaved download/ps5_wp2/wp2_3_sysinit_plan.json")
print("READY FOR ELF BUILDER")
