#!/usr/bin/env python3
"""WP2 STEP 2 — .data/.bss boundary + live-state sanitization analysis.

Facts established in Step 1:
  - kernel IMAGE (VA) = [0xffffffff9e3f0000, 0xffffffffa2224000)
    .text = [0x9e3f0000, 0x9f0b0000)   0xCC0000
    image data+bss = [0x9f0b0000, 0xa2224000)  0x3174000
  - everything >= 0xa2224000 in the dump = RUNTIME heap (excluded from ELF)

This script:
  1. page-level zero/nonzero histogram of the image data range (16KB pages)
     -> locate .rodata / .data / .bss transitions
  2. derive Sony struct mtx layout from 4 known mutexes (Giant, icu, dt, wbinvd)
  3. scan the whole image data for struct mtx instances; report LOCKED ones
  4. dump critical cold-boot landmarks
"""
import sys, struct
sys.path.insert(0, "./scripts")
import wp1_lib as L
import numpy as np

D0, D1 = L.DATA_BASE, 0xFFFFFFFFA2224000      # image data+bss range
off0, off1 = L.va2off(D0), L.va2off(D1)
img = L._blob[off0:off1]
NP = len(img) // 0x4000                        # 16KB pages

print("=" * 100)
print(f"IMAGE DATA RANGE [0x{D0:x}, 0x{D1:x})  size=0x{len(img):x} ({len(img)/2**20:.1f} MiB), {NP} pages of 16KB")
print("=" * 100)

# ---- 1. zero-page histogram -------------------------------------------------
q = np.frombuffer(img, dtype="<u8")
nzq = (q != 0).reshape(NP, 0x4000 // 8).sum(axis=1)      # nonzero qwords per page
allzero = (nzq == 0)

# run-length profile in 256-page (4MB) blocks
print("\n-- density profile (4MB blocks): nonzero-qword fraction, all-zero pages --")
for b in range(0, NP, 256):
    e = min(b + 256, NP)
    blk = nzq[b:e]
    va = D0 + b * 0x4000
    print(f"  0x{va:x}-0x{D0+e*0x4000:x}: nz_qw%={blk.mean()/512*100:6.2f}%  allzero_pages={int((blk==0).sum()):3d}/{e-b}")

# find longest all-zero runs inside the image
print("\n-- longest ALL-ZERO page runs (candidates: pure .bss untouched since boot) --")
runs = []
s = None
for i in range(NP):
    if allzero[i] and s is None:
        s = i
    elif not allzero[i] and s is not None:
        runs.append((s, i - 1))
        s = None
if s is not None:
    runs.append((s, NP - 1))
runs.sort(key=lambda r: r[1] - r[0], reverse=True)
for s, e in runs[:15]:
    print(f"  [0x{D0+s*0x4000:x}, 0x{D0+(e+1)*0x4000:x})  {e-s+1} pages ({(e-s+1)*16} KB)")

# tail analysis: where does 'dense initialized data' end?
print("\n-- tail: last page with >50% nonzero qwords, and zero-fraction per MB near the end --")
dense = np.nonzero(nzq > 1024)[0]
if len(dense):
    print(f"  last dense(>50%) page : 0x{D0+int(dense[-1])*0x4000:x}   (image end 0x{D1:x})")
for mb in range((len(img)//0x100000)-8, len(img)//0x100000):
    a, b2 = mb*0x100000, min((mb+1)*0x100000, len(img))
    blk = q[a//8:b2//8]
    print(f"  MB@0x{D0+a:x}: nz%={float((blk!=0).mean())*100:6.2f}%")

# ---- 2. Sony struct mtx layout from known instances -------------------------
print("\n" + "=" * 100)
print("STRUCT MTX LAYOUT DERIVATION (Giant / icu / descriptor tables / wbinvd)")
print("=" * 100)
known = [
    (0xFFFFFFFFA19288F8, "Giant"),
    (0xFFFFFFFFA1FA8A08, "icu"),
    (0xFFFFFFFFA1FA42F0, "descriptor tables"),
    (0xFFFFFFFFA1FA8A28, "wbinvd"),
    (0xFFFFFFFFA1FA8A48, "l2idsm"),
]
for va, name in known:
    print(f"\n mtx '{name}' @ 0x{va:x}:")
    for k in range(4):
        v = L.read_u64(va + 8 * k)
        s = L.cstr(v, 40) if v and 0xFFFFFFFF9E000000 <= v < 0xFFFFFFFFA8000000 else None
        print(f"   +0x{k*8:02x}: 0x{v:016x}" + (f"   -> {s!r}" if s else ""))
