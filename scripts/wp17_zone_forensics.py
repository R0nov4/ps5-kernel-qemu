#!/usr/bin/env python3
"""WP17-C1c — zone-family forensics.

1. Dump the STATIC designed zone object @0xa18eaf40 (live dump = post-boot
   residue, boot image = pristine) — its hook config (+0x98/+0xa8/+0xb8/
   +0xc0/+0xcc/+0x110) is the DESIGNED template.
2. Scan the whole .text for RIP-relative reads of the zone-table global
   0xa18ea8c0 (and the fill-loop global 0x9fed8b18) — the full usage
   surface of the Zone/Chunk family.
"""
import struct, sys, re
sys.path.insert(0, "./scripts")
import kdis
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

ZONE_STATIC = 0xFFFFFFFFA18EAF40
ZONE_GLOBAL = 0xFFFFFFFFA18EA8C0
FILL_GLOBAL = 0xFFFFFFFF9FED8B18

print("=== [1] STATIC designed zone @0xa18eaf40 (live dump, post-boot residue) ===")
for off, tag in [(0x00,"head"), (0x90,"pre-hook1"), (0x98,"hook1 +0x98"),
                 (0xa8,"hook2 +0xa8"), (0xb0,"import +0xb0"), (0xb8,"hook3 +0xb8"),
                 (0xc0,"hook3arg +0xc0"), (0xc8,"? +0xc8"), (0xcc,"count +0xcc"),
                 (0x108,"? +0x108"), (0x110,"opcnt +0x110")]:
    va = ZONE_STATIC + off
    try:
        v = struct.unpack("<Q", kdis.read(va, 8))[0]
        print(f"  [{va:#x}] (+{off:#05x}) {tag:14s} = {v:#018x}")
    except Exception as e:
        print(f"  [{va:#x}] read fail {e}")

print("\n=== [2] the zone-table GLOBAL cell @0xa18ea8c0 (live dump) ===")
v = struct.unpack("<Q", kdis.read(ZONE_GLOBAL, 8))[0]
print(f"  [0xa18ea8c0] = {v:#018x}")
v2 = struct.unpack("<Q", kdis.read(FILL_GLOBAL, 8))[0]
print(f"  [0x9fed8b18] = {v2:#018x}   (fill-loop arg global)")

print("\n=== [3] if [0xa18ea8c0] is a real zone ptr (live), dump its hooks ===")
if 0xFFFF000000000000 < v < 0xFFFFFFFF00000000 or v > 0xFFFFFFFF80000000:
    pass
if v != 0:
    try:
        for off, tag in [(0x98,"hook1"), (0xa8,"hook2"), (0xb0,"import"),
                         (0xb8,"hook3"), (0xc0,"hook3arg"), (0xcc,"count")]:
            va = v + off
            h = struct.unpack("<Q", kdis.read(va & ~0 if va < 2**64 else va, 8))[0]
            print(f"  [zone+{off:#05x}] {tag:9s} = {h:#018x}")
    except Exception as e:
        print(f"  (live-zone read failed: {e})")

print("\n=== [4] scan .text for RIP-relative refs to 0xa18ea8c0 / 0x9fed8b18 ===")
TEXT_LEN = kdis.DATA_FOFF
text = kdis.IMG[:TEXT_LEN]
KTEXT = kdis.KTEXT
targets = {ZONE_GLOBAL & 0xFFFFFFFF: "zone-global", FILL_GLOBAL & 0xFFFFFFFF: "fill-global"}
hits = []
# brute: every position, try decode 8-byte window; cheap approach: search for
# common load/store encodings with rip-rel32 and verify target
for i in range(0, TEXT_LEN - 8):
    b = text[i:i+8]
    # 48 8b 3d/35/2d/15/0d/05  = mov r64, [rip+rel32]   (and 4c 8b variants)
    if b[0] in (0x48, 0x4C) and b[1] == 0x8B and (b[2] & 0xC7) == 0x05:
        rel = struct.unpack("<i", b, 0)[0] if False else struct.unpack("<i", bytes(b[3:7]))[0]
        tgt = (KTEXT + i + 7 + rel) & 0xFFFFFFFFFFFFFFFF
        t32 = tgt & 0xFFFFFFFF
        if t32 in targets:
            hits.append((KTEXT + i, b[:7].hex(), targets[t32], tgt))
    # 48 89 3d ... = mov [rip+rel32], r64 (writers)
    if b[0] == 0x48 and b[1] == 0x89 and (b[2] & 0xC7) == 0x05:
        rel = struct.unpack("<i", bytes(b[3:7]))[0]
        tgt = (KTEXT + i + 7 + rel) & 0xFFFFFFFFFFFFFFFF
        t32 = tgt & 0xFFFFFFFF
        if t32 in targets:
            hits.append((KTEXT + i, b[:7].hex(), targets[t32] + " (WRITE)", tgt))

for va, hx, tag, tgt in hits:
    print(f"  {va:#x}  {hx:<16} {tag}")
print(f"total: {len(hits)} refs")
