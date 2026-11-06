#!/usr/bin/env python3
"""WP2 STEP 2c — find high-reference boolean globals in .data (cold, flags...).
Method: numpy disp32 sweep over the whole .text (as in wp2_1c), histogram of
RIP-relative targets; report .data targets with >=12 refs whose live value is
a small integer (0/1/2) — these are global flags; 'cold'-style variables must
return to their cold-boot value in the reconstructed image.
"""
import sys, struct
sys.path.insert(0, "./scripts")
import wp1_lib as L
import numpy as np
from collections import Counter

code_start_off = L.va2off(L.CODE_BASE)
blob = L._blob[code_start_off:L.TEXT_SIZE]
base = L.CODE_BASE
n = len(blob)

tgt_count = Counter()
for a in range(4):
    m = (n - a) // 4
    arr = np.frombuffer(blob, dtype="<u4", count=m, offset=a).astype(np.int64)
    arr = np.where(arr >= 0x80000000, arr - 0x100000000, arr)
    pos = np.arange(m, dtype=np.int64) * 4 + a
    # offset-space (avoid int64 overflow with 0xffffffff.... VAs)
    lo = L.DATA_BASE - base
    hi = 0xFFFFFFFFA2224000 - base
    tgt = pos + 4 + arr                 # offset from CODE_BASE
    in_data = (tgt >= lo) & (tgt < hi)
    for t in tgt[in_data]:
        tgt_count[int(t) + base] += 1

print(f"distinct .data RIP-targets: {len(tgt_count)}")
print("\n=== high-ref BOOLEAN-ish globals (>=12 refs, live value small int) ===")
rows = []
for t, c in tgt_count.items():
    if c < 12 or t % 4:
        continue
    v32 = L.read_u32(t)
    if v32 is None or v32 > 2:
        continue
    rows.append((c, t, v32))
rows.sort(reverse=True)
for c, t, v in rows[:60]:
    # how many of the refs are cmp/test (read) vs mov (write)? approximate by context strings
    print(f"  0x{t:x}: refs={c:4d}  live_u32={v}")

# Also: the specific suspects from FreeBSD lore
print("\n=== specific suspects ===")
for t, name in [(0xFFFFFFFFA1978190, "boothowto"), (0xFFFFFFFFA1978198, "mi_aux2"),
                (0xFFFFFFFFA19781A0, "mi_aux1"), (0xFFFFFFFFA19781A8, "mi_end"),
                (0xFFFFFFFFA19781B0, "mi_being_run")]:
    print(f"  {name} @0x{t:x}: live=0x{L.read_u64(t):016x}  refs={tgt_count.get(t,0)}")
