#!/usr/bin/env python3
"""WP11 Phase D fix #1 (targeted) — surgical residue wipe.

Wipes ONLY:
  1. .data qwords pointing into the seed area DMAP(0x3F000000..0x40000000)
     (36 hits — provably bad: live-dump queue/object pointers into the seed
      region that is fresh-zero in our VM; includes [0xa18ea8f8]=0x3F0122E0,
      the direct cause of the 0x9e8b6c71 mtx_lock crash)
  2. [0xa18ea840] -> DMAP(0x1E1FC000) (below-kernel staging garbage in the
     same queue-registry struct)
Excludes: W4/W6 statics and any trampoline patch-table byte ranges
(learned the hard way: mass below-kernel wipe -> "patch mismatch at
21910402" halt).
"""
import struct
import time

T0 = time.time()
KTEXT = 0x9E3F0000
KDATA = 0x9F0B0000
DMAP = 0xFFFF8E7700000000
KIT = "./kit_build/wp3_boot/kernel_raw.bin"
ELF = "./kit_build/wp3_boot/trampoline.elf"

EXCLUDE = {0xA1CF3F10, 0xA093E6A0}
EXTRA = {0xA18EA840: 0xFFFF8E771E1FC000}

kit = bytearray(open(KIT, "rb").read())
elf = open(ELF, "rb").read()

# --- parse trampoline patch_table ranges (img offsets) ---
first = struct.pack("<II", 0x00C16A19, 3) + bytes([15, 1, 217]) + bytes([49, 192, 144])
pos = elf.find(first)
assert pos >= 0
patch_ranges = []
p = pos
for n in range(676):
    off, ln = struct.unpack_from("<II", elf, p)
    patch_ranges.append((off, ln))
    p += 8 + 2 * ln


def in_patch_range(img_off):
    return any(o <= img_off < o + ln for o, ln in patch_ranges)


# --- seed-window scan ---
NEEDLE = struct.pack("<I", 0xFFFF8E77)
SEED_LO, SEED_HI = 0x3F000000, 0x40000000
DATA_OFF = KDATA - KTEXT
hits = []
scan_pos = DATA_OFF
end = len(kit) - 4
while True:
    o = bytes(kit).find(NEEDLE, scan_pos, end)
    if o < 0:
        break
    scan_pos = o + 1
    base = o - 4
    if base < DATA_OFF or (base & 7):
        continue
    low = struct.unpack_from("<I", kit, base)[0]
    if not (SEED_LO <= low < SEED_HI):
        continue
    va = KTEXT + base
    if va in EXCLUDE or in_patch_range(base):
        continue
    v = struct.unpack_from("<Q", kit, base)[0]
    hits.append((va, v))

print(f"seed-window hits: {len(hits)}")
wiped = 0
for va, v in hits:
    off = va - KTEXT
    kit[off:off + 8] = b"\x00" * 8
    wiped += 1
    print(f"  wipe {va:#x}: {v:#018x} -> 0   (phys {v - DMAP:#x})")

# --- targeted extra ---
for va, expect in EXTRA.items():
    off = va - KTEXT
    cur = struct.unpack_from("<Q", kit, off)[0]
    if cur == expect and not in_patch_range(off):
        kit[off:off + 8] = b"\x00" * 8
        wiped += 1
        print(f"  wipe {va:#x}: {cur:#018x} -> 0   (below-kern queue-registry)")
    else:
        print(f"  SKIP {va:#x}: cur={cur:#018x} (expect {expect:#018x})")

open(KIT, "wb").write(kit)
print(f"\nwiped {wiped} pointers total -> {KIT} ({time.time()-T0:.2f}s)")
