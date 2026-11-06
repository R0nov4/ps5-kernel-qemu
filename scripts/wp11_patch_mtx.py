#!/usr/bin/env python3
"""WP11 fix #2 — mtx_lock zero-lock force-acquire (the 0x9e8b6c71 CR2=0x400 fix).

Root cause: UMA bootstrap (stage #48, 'UMA Zones'/'UMA Kegs') allocates zone
objects whose backing memory is fresh-zero seed area; the embedded mutexes'
lock words are 0 (never mtx_init'd) -> mtx_lock's adaptive spin dereferences
owner NULL+0x400.

Patch (fast path of mtx_lock @0x9e8b6a00):
  0x9e8b6a34: 75 27 (jne slow)      -> 77 27 (ja  slow)
      lock words 0..4 now take the fast path (4=FREE, 0=uninitialized)
  0x9e8b6a36: b8 04 00 00 00 (mov eax,4) -> 90 x5 (nops)
      CAS expected value stays rax = the actual current lock word, so an
      uncontended zero-lock acquires atomically (0 -> curthread). Real owned
      locks (rax>4) still take the slow path — no lock stealing.
"""
import sys

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

img = bytearray(open(IMG, "rb").read())

patches = [
    ("jne->ja (allow 0..4)", 0x9E8B6A34, bytes.fromhex("7527"), bytes.fromhex("7727")),
    ("kill mov eax,4 (CAS expects rax)", 0x9E8B6A36, bytes.fromhex("b804000000"), b"\x90" * 5),
]

fail = 0
for name, va, expect, new in patches:
    off = va - KTEXT
    cur = bytes(img[off:off + len(new)])
    if cur != expect:
        print(f"FAIL {name} @ {va:#x}: expected {expect.hex()}, found {cur.hex()}")
        fail += 1
        continue
    img[off:off + len(new)] = new
    print(f"OK   {name:34s} @ {va:#x}: {expect.hex()} -> {new.hex()}")

if fail:
    sys.exit(1)
open(IMG, "wb").write(img)
print(f"\nmtx_lock zero-lock patch applied -> {IMG}")
