#!/usr/bin/env python3
"""WP11 fix #5 — 0x9e82f4f0 tail-callback guard.

The zone 'release' callback at [template+0xa8] is NULL on the cold image;
0x9e82f4f0 tail-jumps to it (`jmp rcx` @0x9e82f5d2) after the epilogue ->
IP=0 crash. CFI check fails too but cfi_check_fail is already a ret-stub
(WP7), so the jmp still executes.

Patch: `pop rbp; jmp rcx` (5d ff e1) -> `pop rbp; ret; nop` (5d c3 90) —
return to the caller instead of jumping through the (possibly NULL)
callback. The callback is a release/fini hook; skipping it during boot is
tolerable.
"""
import sys

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

ORIG = bytes.fromhex("5dffe1")
NEW = bytes.fromhex("5dc390")

img = bytearray(open(IMG, "rb").read())
off = 0x9E82F5D1 - KTEXT
cur = bytes(img[off:off + 3])
if cur != ORIG:
    print(f"FAIL: expected {ORIG.hex()}, found {cur.hex()}")
    sys.exit(1)
img[off:off + 3] = NEW
open(IMG, "wb").write(img)
print(f"OK tail-jmp guard @ 0x9e82f5d1: {ORIG.hex()} -> {NEW.hex()}")
