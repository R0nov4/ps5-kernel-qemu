#!/usr/bin/env python3
"""wp7_residue_scan.py — systematic scan of kernel .data for dangerous live-residue
DMAP pointers (phys > 1GB → outside our flat 1GB DMAP window → guaranteed fault).

Ranges flagged (DMAP base 0xffff8e7700000000):
  0xffff8e7740000000 .. 0xffff8e777fffffff   phys [1GB, 2GB)   app region
  0xffff8e7780000000 .. 0xffff8e77ffffffff   phys >= 2GB        beyond QEMU RAM
Only img offsets >= 0xCC0000 (.data segment) are scanned.
"""
import struct

RAW = "./wp3_boot/kernel_raw_wp6.bin"   # un-WP7-patched image
KTEXT = 0x9E3F0000
DATA_OFF = 0xCC0000
DMAP = 0xFFFF8E7700000000

img = open(RAW, "rb").read()
hits = []
for off in range(DATA_OFF, len(img) - 8, 8):
    q = struct.unpack_from("<Q", img, off)[0]
    if 0xFFFF8E7740000000 <= q <= 0xFFFF8E77FFFFFFFF:
        va = KTEXT + off
        hits.append((va, q, q - DMAP))

print(f"dangerous DMAP>1GB residue qwords in .data: {len(hits)}")
for va, q, phys in hits:
    print(f"  va {va:#014x}  ->  {q:#018x}  (phys {phys:#010x})")
