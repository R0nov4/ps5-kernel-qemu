#!/usr/bin/env python3
"""Q3 hunt: (a) savectx callers -> susppcb global in .data
(b) other 0x1DD/0x1DE readers (semantic clues)
(c) 3rd write block context (0x9e647f80)
(d) scan the WHOLE dump for live extended trap frames holding the 8 MSR values.
"""
import sys, struct
sys.path.insert(0, "./scripts")
import wp1_lib as L
import numpy as np
from collections import Counter

SAVECTX = 0xFFFFFFFF9E6427D0

print("=" * 96)
print("(a) XREFS to savectx 0xffffffff9e6427d0")
print("=" * 96)
calls = []
for op, nm in ((0xE8, "call"), (0xE9, "jmp")):
    i = 0
    while True:
        i = L.text.find(bytes([op]), i)
        if i == -1 or i + 5 > L.TEXT_SIZE:
            break
        rel = struct.unpack_from("<i", L.text, i + 1)[0]
        t = L.TEXT_BASE + i + 5 + rel
        if t == SAVECTX and L.in_code(L.TEXT_BASE + i):
            ok, _ = L.aligned_reachable(L.TEXT_BASE + i, maxback=64)
            calls.append((L.TEXT_BASE + i, nm, ok))
        i += 1
for va, nm, ok in calls:
    f, _ = L.containing_function(va)
    print(f"  {nm} @0x{va:x} aligned={ok} in func 0x{f:x}")
print(f"  data ptrs to savectx: {[hex(x) for x in L.data_ptrs_to(SAVECTX)]}")

# disasm around each caller to find the RDI argument (susppcb global)
for va, nm, ok in calls:
    print(f"\n  -- caller context @0x{va:x} --")
    print(L.disasm_str(va - 0x40, 0x70, maxins=24, mark_va=va))

print()
print("=" * 96)
print("(b) OTHER readers of MSR 0x1DD (semantic clue) — from wp1_2 verified sites")
print("=" * 96)
import json
d = json.load(open("./download/ps5_wp1/wp1_2_msr.json"))
r1dd = [s for s in d["verified_sites"] if s.get("ecx") and s["ecx"].endswith("0x1dd")]
print(f"  0x1dd sites: {len(r1dd)}")
by_func = Counter(s["func"] for s in r1dd)
for f, c in by_func.most_common(12):
    print(f"    func 0x{f}: {c} sites")
# pick 2 distinct non-stub functions and show usage
seen = set()
for s in r1dd:
    f = int(s["func"], 16) if isinstance(s["func"], str) else s["func"]
    if f in (0xFFFFFFFF9E6428F0, 0xFFFFFFFF9E645010) or f in seen:
        continue
    seen.add(f)
    va = int(s["va"], 16) if isinstance(s["va"], str) else s["va"]
    print(f"\n  -- 0x1dd read @0x{va:x} in func 0x{f:x} --")
    print(L.disasm_str(va - 0x30, 0x60, maxins=18, mark_va=va))
    if len(seen) >= 3:
        break

print()
print("=" * 96)
print("(c) 3rd write block context 0x9e647f80..0x9e648120")
print("=" * 96)
print(L.disasm_str(0xFFFFFFFF9E647F80, 0x90, maxins=30))

print()
print("=" * 96)
print("(d) WHOLE-DUMP scan for live extended trap frames")
print("=" * 96)
# Frame signature (from entry stubs):
#   [+0x80..0x87] RIP: kernel text VA (or 0)
#   [+0x88] dword: flags in {1, 8, 9} (we accept 0..0xF)
#   [+0x90..0xd8]: 10 qwords = MSR values
# Validation strategy: the frame must ALSO have [+0xe0] RFLAGS with plausible shape
# (upper 32 bits zero, bit1=1) and [+0x80] RIP either 0 or in kernel text.
blob = L._blob
n = len(blob)
arr = np.frombuffer(blob, dtype="<u8")

hits = 0
found = {}
# scan qword-aligned: check [off+0x88>>3] dword in {1,8,9} AND [off+0x80] rip valid
# rip qword at byte off+0x80 -> qword index k+16; flags dword at k+17
# MSRs at k+18..k+27 (0x90..0xd8); rflags at k+28 (0xe0)
k = 0
cand = 0
examples = []
while k + 29 < len(arr):
    rip = int(arr[k + 16])
    flags_dw = int(arr[k + 17]) & 0xFFFFFFFF
    rflags = int(arr[k + 28])
    if (flags_dw in (1, 8, 9)) and (rip == 0 or L.in_code(rip)) and (rflags & 0xFFFFFFFF) != 0 and (rflags >> 32) == 0 and (rflags & 2):
        # segment words fs/gs/es/ds at 0x7c,0x7e,0x8c,0x8e must be small selectors
        segs = blob[(k * 8) + 0x7c:(k * 8) + 0x80] + blob[(k * 8) + 0x8c:(k * 8) + 0x90]
        fs, gs = struct.unpack("<HH", blob[(k*8)+0x7c:(k*8)+0x80])
        es, ds = struct.unpack("<HH", blob[(k*8)+0x8c:(k*8)+0x90])
        if max(fs, gs, es, ds) < 0x40:
            cand += 1
            msrvals = [int(arr[k + 18 + j]) for j in range(10)]
            examples.append((k * 8, rip, flags_dw, rflags, msrvals))
    k += 1

print(f"  candidate frames found: {cand}")
# aggregate the MSR values
if examples:
    from collections import defaultdict
    valsets = defaultdict(list)
    for off, rip, fl, rf, vals in examples:
        key = tuple(vals)
        valsets[key].append((off, rip, fl))
    print(f"  distinct 10-MSR value sets: {len(valsets)}")
    for key, lst in sorted(valsets.items(), key=lambda kv: -len(kv[1]))[:12]:
        offs = ", ".join(f"0x{o:x}" for o, _, _ in lst[:4])
        print(f"    x{len(lst):3d} @[{offs}]")
        print(f"        1DD={key[0]:#018x} 1DE={key[1]:#018x}")
        for j in range(8):
            print(f"        C000011{j} = {key[2+j]:#018x}")
