#!/usr/bin/env python3
"""wp6_sysinit_stats.py — analyze sysinit_set from the reconstructed ELF image.
Confirms: entry layout {u32 sub; u32 order; fn* thunk; ...; udata@+0x10/+0x20},
runnable entries (sub>=2), pre-stamped done (sub==1), dummies (sub==0), nulls.
"""
import struct
from collections import Counter

ELF = "./download/ps5_kernel_1360_reconstructed.elf"
T_OFF, T_SZ = 0x1000, 0xCC0000
D_OFF, D_SZ = 0xCC1000, 0x3174000
blob = open(ELF, "rb").read()

def va2img(va):
    lo = va & 0xFFFFFFFF
    if 0x9E3F0000 <= lo < 0x9F0B0000: return lo - 0x9E3F0000
    if 0x9F0B0000 <= lo < 0xA2224000: return 0xCC0000 + (lo - 0x9F0B0000)
    raise ValueError(hex(va))

def rd(va, n):
    o = va2img(va)
    if o < 0xCC0000: return blob[T_OFF+o:T_OFF+o+n]
    return blob[D_OFF+(o-0xCC0000):D_OFF+(o-0xCC0000)+n]

SET_LO, SET_HI = 0x9FE51FB0, 0x9FE55488
total_slots = (SET_HI - SET_LO) // 8
entries = []
for i in range(total_slots):
    p = struct.unpack("<Q", rd(SET_LO + 8*i, 8))[0]
    if p == 0:
        entries.append(None)
        continue
    sub, order = struct.unpack("<II", rd(p, 8))
    fn = struct.unpack("<Q", rd(p + 8, 8))[0]
    fn2 = struct.unpack("<Q", rd(p + 0x18, 8))[0]
    udata = struct.unpack("<Q", rd(p + 0x10, 8))[0]
    udata2 = struct.unpack("<Q", rd(p + 0x20, 8))[0]
    entries.append(dict(sub=sub, order=order, fn=fn, fn2=fn2,
                        udata=udata, udata2=udata2, va=p))

nonnull = [e for e in entries if e]
subs = Counter(e["sub"] for e in nonnull)
print(f"slots total      : {total_slots}")
print(f"null slots       : {total_slots - len(nonnull)}")
print(f"non-null entries : {len(nonnull)}")
print(f"sub histogram    : {dict(sorted(subs.items()))}")
runnable = [e for e in nonnull if e["sub"] >= 2]
done     = [e for e in nonnull if e["sub"] == 1]
dummy    = [e for e in nonnull if e["sub"] == 0]
print(f"pre-stamped done (sub==1) : {len(done)}")
print(f"dummy/skip     (sub==0)   : {len(dummy)}")
print(f"RUNNABLE       (sub>=2)   : {len(runnable)}")

# null-run map: where are the holes?
holes = []
in_hole = False
for i, e in enumerate(entries):
    if e is None and not in_hole:
        in_hole, h0 = True, i
    elif e is not None and in_hole:
        in_hole = False
        holes.append((h0, i-1))
if in_hole: holes.append((h0, total_slots-1))
print(f"null holes (slot idx ranges): {[(a,b) for a,b in holes]}")

# runnable sorted execution order (by sub, then order — matches mi_startup insertion sort)
run_sorted = sorted(runnable, key=lambda e: (e["sub"], e["order"]))
print("\nfirst 25 runnable in sorted (sub,order) order:")
for k, e in enumerate(run_sorted[:25]):
    print(f"  #{k:4d} sub={e['sub']:#010x} ord={e['order']:#010x} fn={e['fn']:#x} udata={e['udata']:#x}")
print("\nlast 10 runnable:")
for k, e in enumerate(run_sorted[-10:]):
    print(f"  #{len(run_sorted)-10+k:4d} sub={e['sub']:#010x} ord={e['order']:#010x} fn={e['fn']:#x} udata={e['udata']:#x}")

# where is the appmem-profile sysinit func? (0x9edfe... area funcs)
print("\nrunnable entries whose fn is in 0x9edf8000..0x9ee00000 (mem-config area):")
for k, e in enumerate(run_sorted):
    if 0x9edf8000 <= (e["fn"] & 0xFFFFFFFF) < 0x9ee00000:
        print(f"  sorted#{k:4d} sub={e['sub']:#010x} fn={e['fn']:#x} udata={e['udata']:#x}")

# struct sanity for one known entry (from WP1 json idx1: thunk 0x9e654e60 func 0x9ef918c0)
e = nonnull[1]
print(f"\nentry[1] @ {e['va']:#x}: sub={e['sub']:#x} ord={e['order']:#x} fn={e['fn']:#x} fn2={e['fn2']:#x}")
print(f"  fn 0x9e654e60 is a THUNK -> real target? dump: {rd(e['fn'],12).hex()}")
