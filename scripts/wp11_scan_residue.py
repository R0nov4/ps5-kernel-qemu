#!/usr/bin/env python3
"""WP11 Phase D fix #1 — wipe residue .data pointers into the seed area
(DMAP phys [0x3F000000, 0x40000000)) and the below-kernel staging window
(DMAP phys [0x100000, 0x1E3F0000)).

Cold-boot semantics: the kernel must ALLOCATE these queues fresh instead of
re-initializing live-dump residue pointers (root cause of the 0x9e8b6c71
mtx_lock crash at stage acpi_throttle / vm-pagequeue creation).

Excludes (WP9/WP7-baked legit statics):
  0xa1cf3f10  W4 bitmap ptr  -> DMAP(0x3F001000)
  0xa093e6a0  W6 list-tail   -> DMAP(0x3F000008)
Classification vs the pre-WP7 wp6 image: same value in both = original
live-dump residue (wipe); kit-only = WP7-baked (keep).
"""
import struct
import time

T0 = time.time()
KTEXT = 0x9E3F0000
KDATA = 0x9F0B0000
DMAP = 0xFFFF8E7700000000
KIT = "./kit_build/wp3_boot/kernel_raw.bin"
WP6 = "./wp3_boot/kernel_raw_wp6.bin"

EXCLUDE = {0xA1CF3F10, 0xA093E6A0}
DATA_OFF = KDATA - KTEXT          # 0xCC0000, 8-aligned

kit = open(KIT, "rb").read()
wp6 = open(WP6, "rb").read()

SEED_LO, SEED_HI = 0x3F000000, 0x40000000
BELOW_LO, BELOW_HI = 0x00100000, 0x1E3F0000
NEEDLE = struct.pack("<I", 0xFFFF8E77)   # high dword of any DMAP pointer

hits = []
pos = DATA_OFF
end = len(kit) - 4
while True:
    o = kit.find(NEEDLE, pos, end)
    if o < 0:
        break
    pos = o + 1
    base = o - 4                       # qword file offset
    if base < DATA_OFF or (base & 7):
        continue
    low = struct.unpack_from("<I", kit, base)[0]
    if not (SEED_LO <= low < SEED_HI or BELOW_LO <= low < BELOW_HI):
        continue
    va = KTEXT + base
    if va in EXCLUDE:
        continue
    v = struct.unpack_from("<Q", kit, base)[0]
    v6 = struct.unpack_from("<Q", wp6, base)[0]
    origin = "RESIDUE(orig)" if v6 == v else "WP7-baked"
    hits.append((va, v, origin))

print(f"scan done in {time.time()-T0:.2f}s — {len(hits)} hits\n")
print(f"{'VA':>20} {'value':>20}  origin         phys")
wiped = 0
img = bytearray(kit)
for va, v, origin in hits:
    tag = "SEED" if SEED_LO <= (v & 0xFFFFFFFF) < SEED_HI else "BELOW-KERN"
    print(f"{va:#018x} {v:#018x}  {origin:13s} {v - DMAP:#010x} {tag}")
    if origin == "RESIDUE(orig)":
        off = va - KTEXT
        img[off:off + 8] = b"\x00" * 8
        wiped += 1

print(f"\nwiped {wiped} residue pointers (kept {len(hits) - wiped} WP7-baked)")
open(KIT, "wb").write(img)
print(f"written -> {KIT} in {time.time()-T0:.2f}s total")
