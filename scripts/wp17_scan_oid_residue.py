#!/usr/bin/env python3
"""WP17-C9 — fast scan: OID-style static objects with residue parents.

Strategy: a residue parent [+8] (0 < v < 0x10000) = 8 bytes 'XX XX 00 00
00 00 00 00' — find the 6-zero runs in .data directly (rare), then verify
the [+0x30] name-ptr pattern and read the LIVE dump's designed link.
"""
import struct

LIVE = "./ps5/dump13/kernel-13.60-live.bin"
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
KTEXT = 0x9E3F0000

live = open(LIVE, "rb").read()
img = open(IMG, "rb").read()

LO = 0x9F0B0000
off_lo = LO - KTEXT
Z6 = b"\x00" * 6
hits = []
pos = off_lo
end = len(img) - 0x40
while True:
    pos = img.find(Z6, pos, end)
    if pos < 0:
        break
    qpos = pos & ~7               # the qword containing this zero run
    off = qpos
    p8 = struct.unpack_from("<Q", img, off)[0]
    if 0 < p8 <= 0xFFFF and (pos - qpos) <= 2:
        p30 = struct.unpack_from("<Q", img, off + 0x30)[0]
        if 0xFFFFFFFF9E000000 < p30 < 0xFFFFFFFFA2200000:
            va = KTEXT + off
            lp8 = struct.unpack_from("<Q", live, off)[0] if off + 8 <= len(live) else 0
            hits.append((va, p8, lp8, p30))
    pos += 6

# de-dup (the same qword can be found via multiple zero runs)
seen = set()
uniq = []
for h in hits:
    if h[0] in seen:
        continue
    seen.add(h[0])
    uniq.append(h)

print(f"{'obj':>14} {'img[+8]':>10} {'live[+8]':>20} {'name[+0x30]':>14}")
for va, p8, lp8, p30 in uniq:
    print(f"{va:#14x} {p8:#10x} {lp8:#20x} {p30:#14x}")
print(f"total residue-parent candidates: {len(uniq)}")
