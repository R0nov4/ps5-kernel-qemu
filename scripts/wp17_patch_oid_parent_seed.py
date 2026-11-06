#!/usr/bin/env python3
"""WP17 #7 — the sysctl OID-tree parent seed (the residue-family fix).

ROOT CAUSE (GDB wp17_gdb_c7/c8 + the image-vs-live diff scan):
  The SYSINIT stage after the eventtimer registration walks the sysctl OID
  tree's PARENT chain (the walker 0x9e9467c0: [obj+8] = the parent,
  [obj+0x30] = the name; phase 2 @0x9e946a00 reads [rbx+0x30] per element
  building the dotted path 'child.parent....root', terminating at the root
  0xffffffffa197a5a0).
  The STATIC top-level OID branch nodes carry LIVE RESIDUE in their parent
  field (img [+8] = 4) where the LIVE dump holds the designed link:
    'vfs'        0xa095a380 -> root
    'net'        0xa095a3e0 -> root
    'hw'         0xa095a500 -> root
    'user'       0xa095a560 -> root
    'p1003_1b'   0xa095a5c0 -> root
    'kern'       0xa095c4b0 -> root      <- THE crash: LAPIC-timer's
                                            chain hit 'kern'+8 = 4 ->
                                            'mov rdi,[rbx+0x30]' CR2=0x34
    'debug.acpi.enable_debug_objects' 0xa0fe86d8 -> 0xffffffffa2187830
    0x9febef18 -> 0xffffffffa1964000    (encrypted names)
    0xa05f89b0 -> 0xffffffffa1d8da90

FIX — the systemic base-field seed (the user's WP17 directive): image-write
  the 9 designed parents (the LIVE dump's compile-time tree links). The
  whole OID walker family (every 'can't re-use a leaf' registration's
  path-walk) now terminates at the designed root.
"""
import struct
import sys

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
LIVE = "./ps5/dump13/kernel-13.60-live.bin"

ROOT = 0xFFFFFFFFA197A5A0
SEEDS = [
    # (object base, name for the log, designed parent)
    (0xA095A380, "vfs",       ROOT),
    (0xA095A3E0, "net",       ROOT),
    (0xA095A500, "hw",        ROOT),
    (0xA095A560, "user",      ROOT),
    (0xA095A5C0, "p1003_1b",  ROOT),
    (0xA095C4B0, "kern",      ROOT),
    (0xA0FE86D8, "debug.acpi.enable_debug_objects", 0xFFFFFFFFA2187830),
    (0x9FEBEF18, "(enc-A)",   0xFFFFFFFFA1964000),
    (0xA05F89B0, "(enc-B)",   0xFFFFFFFFA1D8DA90),
]

img = bytearray(open(IMG, "rb").read())
live = open(LIVE, "rb").read()

for base, name, parent in SEEDS:
    off = base + 8 - KTEXT
    cur = struct.unpack_from("<Q", img, off)[0]
    live_v = struct.unpack_from("<Q", live, off)[0]
    if cur == parent:
        print(f"  {base:#x} ({name}): parent already {parent:#x} (idempotent)")
        continue
    if cur != 4 or live_v != parent:
        print(f"  WARN {base:#x} ({name}): img={cur:#x} live={live_v:#x} — expected residue 4 / designed {parent:#x}")
        if live_v != parent:
            print(f"    (live differs from the designed value — seeding the designed link anyway)")
    img[off:off+8] = struct.pack("<Q", parent)
    print(f"  {base:#x} ({name}): parent {cur:#x} -> {parent:#x}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP17#7: sysctl OID-tree parent seed (9 residue links restored)")
