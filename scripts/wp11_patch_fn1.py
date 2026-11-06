#!/usr/bin/env python3
"""WP11 fix #3 — fn1 (queue/zone init @0x9e82d7f0): null-safe init callback.

The ghost zone objects (runtime-allocated into the seed area, all-zero) have
a NULL init callback at [obj+0xa0]; fn1 calls it unconditionally ->
call NULL -> IP=0 crash.

Patch (12 bytes at 0x9e82d8c2..0x9e82d8ce):
  original:  and ecx,0x8000 ; or ecx,r12d ; call r15
  patched:   test r15,r15 ; jz +7 ; nop nop ; call r15 ; nop nop
NULL callback -> skip the call entirely. The ecx flag-mask computation is
dropped (arg4 of the callback; cosmetic for the remaining callers).
"""
import sys

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

ORIG = bytes.fromhex("81e100800000") + bytes.fromhex("4409e1") + bytes.fromhex("41ffd7")
NEW = bytes.fromhex("4d85ff") + bytes.fromhex("7407") + b"\x90\x90" + bytes.fromhex("41ffd7") + b"\x90\x90"
assert len(ORIG) == 12 and len(NEW) == 12

img = bytearray(open(IMG, "rb").read())
off = 0x9E82D8C2 - KTEXT
cur = bytes(img[off:off + 12])
if cur != ORIG:
    print(f"FAIL: expected {ORIG.hex()}, found {cur.hex()}")
    sys.exit(1)
img[off:off + 12] = NEW
open(IMG, "wb").write(img)
print(f"OK fn1 null-callback guard @ 0x9e82d8c2: {ORIG.hex()} -> {NEW.hex()}")
