#!/usr/bin/env python3
"""WP17 #4 — the systemic malloc/zone-import bump-window extension
         (cave50 / cave56 / cave51 — surgical imm patches).

THE USER'S WP17 DIRECTIVE #2:
  The current shared bump window [0x3F1A1000, 0x3F200000) is only 380KB —
  the late SYSINIT stages perform many allocations (the 0xF3500 hash table
  alone is ~1MB) and would exhaust it mid-boot.

GEOMETRY (seed-area ledger + WP14's design):
  [0x3F1A1000, 0x3F200000)  the current 380KB window (cave50/56 state
                             @0x3F1A0830) — ~44KB consumed at the crash;
  [0x3F200000, 0x3F740000)   FREE: the gap between the malloc window and
                             the WP14 arena node chains — untouched,
                             zeroed DMAP memory;
  [0x3F740000, 0x3F770000)   the 3 arena node-chain arrays (WP14) — LIVE;
  [0x3F770000, 0x40000000)   the WP14 extent pool (cave22's serves + the
                             W1 v3 extension slices) — LIVE, must NOT be
                             handed out by the malloc bump.

FIX — the ceiling 0x3F200000 -> 0x3F740000 (5.6MB total, a 14.7x extension
  that spans the user's [0x3F500000, ...) range while staying clear of the
  node chains and the shared pool — no collisions by construction):
    cave50 @0x9E40122F: 'cmp r11d, 0x3F200000' imm32 -> 0x3F740000
    cave56 @0x9E401538: 'cmp r11d, 0x3F200000' imm32 -> 0x3F740000
    cave51 @0x9E401291: 'movabs r10, 0xFFFF8E773F200000' imm64
                        -> 0xFFFF8E773F740000 (the free-noop range match)
"""
import sys
import struct

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

OLD_CEIL = 0x3F200000
NEW_CEIL = 0x3F740000

SITES = [
    # (name, cave VA, offset-in-cave of the imm, kind, old bytes, new bytes)
    ("cave50 cmp imm32", 0x9E401200, 0x22E - 0x200, "imm32",
     struct.pack("<I", OLD_CEIL), struct.pack("<I", NEW_CEIL)),
    ("cave56 cmp imm32", 0x9E401500, 0x537 - 0x500, "imm32",
     struct.pack("<I", OLD_CEIL), struct.pack("<I", NEW_CEIL)),
    ("cave51 movabs imm64", 0x9E401280, 0x291 - 0x280, "imm64",
     struct.pack("<Q", 0xFFFF8E773F200000), struct.pack("<Q", 0xFFFF8E773F740000)),
]

img = bytearray(open(IMG, "rb").read())

for name, cave, off_in, kind, old, new in SITES:
    off = cave - KTEXT + off_in
    cur = bytes(img[off:off+len(old)])
    if cur == new:
        print(f"{name}: already {NEW_CEIL:#x} (idempotent)")
        continue
    if cur != old:
        print(f"FAIL {name} @ {cave+off_in:#x}: {cur.hex()} != {old.hex()}"); sys.exit(1)
    img[off:off+len(new)] = new
    print(f"{name} @ {cave+off_in:#x}: {OLD_CEIL:#x} -> {NEW_CEIL:#x}  [{'%#x' % (NEW_CEIL-0x3F1A1000)} window]")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print(f"OK WP17#4: malloc/zone-import bump window -> [0x3F1A1000, {NEW_CEIL:#x}) = {(NEW_CEIL-0x3F1A1000)//1024}KB")
