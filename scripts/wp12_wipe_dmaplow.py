#!/usr/bin/env python3
"""WP12 fix #4 (systemic) — wipe live-dump DMAP pointers into non-kernel RAM.

Root cause of the stage-49+ strcmp-GPF family: the live dump's .data holds
thousands of pointers to runtime objects allocated by the LIVE machine at
phys below the kernel image (module/staging area 16MB..484MB) and above it
(PHYSFREE 0x22225000..1GB).  In our VM that RAM holds the stale module copy
or free pages -> the kernel walks these residue chains into poison values
(e.g. the keg-hash bucket chain ending at DMAP(0x1911880) with
name=0x3000112ff08e9fa -> GPF in strcmp @0x9ea1d440).

Cold-boot semantics: runtime-built structures must start EMPTY.  Wipe every
.data qword = DMAP(0xffff8e77........) with phys in
    [0x01000000, 0x1E3F0000)   (below the kernel image; module copy / staging)
    [0x22225000, 0x40000000)   (above the kernel image; PHYSFREE..1GB)
Excluded: trampoline patch-table byte ranges (WP11 lesson: blanket wipe
without this halts at 'patch mismatch'), the W4 bitmap / W6 list-tail
statics, and the msgbuf hole below 16MB (auto: window starts at 16MB).
"""
import struct
import time

T0 = time.time()
KTEXT = 0x9E3F0000
KDATA = 0x9F0B0000
DMAP = 0xFFFF8E7700000000
KIT = "./kit_build/wp3_boot/kernel_raw.bin"
ELF = "./kit_build/wp3_boot/trampoline.elf"

EXCLUDE_VA = {0xA1CF3F10, 0xA093E6A0}          # W4 bitmap / W6 list-tail statics
WINDOWS = [(0x01000000, 0x1E3F0000), (0x22225000, 0x40000000)]

kit = bytearray(open(KIT, "rb").read())
elf = open(ELF, "rb").read()

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


NEEDLE = struct.pack("<I", 0xFFFF8E77)
DATA_OFF = KDATA - KTEXT
hits = []
scan_pos = DATA_OFF
end = len(kit) - 4
blob = bytes(kit)
while True:
    o = blob.find(NEEDLE, scan_pos, end)
    if o < 0:
        break
    scan_pos = o + 1
    base = o - 4
    if base < DATA_OFF or (base & 7):
        continue
    low = struct.unpack_from("<I", kit, base)[0]
    if not any(lo <= low < hi for lo, hi in WINDOWS):
        continue
    va = KTEXT + base
    if va in EXCLUDE_VA or in_patch_range(base):
        continue
    v = struct.unpack_from("<Q", kit, base)[0]
    hits.append((va, v))

print(f"DMAP-low residue hits: {len(hits)}")
for va, v in hits[:8]:
    print(f"  e.g. {va:#x}: {v:#018x} (phys {v - DMAP:#x})")

wiped = 0
for va, v in hits:
    off = va - KTEXT
    kit[off:off + 8] = b"\x00" * 8
    wiped += 1

# sanity: msgbuf statics must survive (phys < 16MB)
for chk, want in [(0xA1FB8A60, 0xF00000), (0xA1FB8A68, 0xF17FB8)]:
    cur = struct.unpack_from("<Q", kit, chk - KTEXT)[0]
    print(f"  sanity {chk:#x}: {cur:#018x} (phys {cur - DMAP:#x}) -> {'OK' if cur - DMAP == want else 'CHANGED!'}")

open(KIT, "wb").write(kit)
print(f"wiped {wiped} below-kernel/above-kernel DMAP residue pointers ({time.time()-T0:.2f}s)")
