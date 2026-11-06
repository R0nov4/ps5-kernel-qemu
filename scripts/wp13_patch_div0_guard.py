#!/usr/bin/env python3
"""WP13 fix #17 — MSR-frequency divide-by-zero guard (trap 18 @0x9ed5a412).

The clockrate stage computes F = (MSR0xE8 * 1600) / MSR0xE7 via:
    rdmsr(0xE7) -> edi:esi ; rdmsr(0xE8) -> rdx:rax
    or rdi, rsi            ; rdi = 64-bit MSR0xE7 divisor
    ... xor edx,edx ; div rdi   (or div edi — 32-bit path)
QEMU does not implement MSR 0xE7/0xE8 -> both read 0 -> div by 0 -> trap 18.

Fix: 0x9ed5a3fd 'or rdi, rsi' (48 09 f7) -> 'or edi, 1' (83 cf 01):
the divisor can never be zero; with the MSRs reading 0 the quotient is 0
(frequency prints as 0 — cold-boot garbage, no crash). rdi is only used as
the divisor here (reloaded for the printf afterwards).
"""
import sys

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
SITE = 0x9ed5a3fd
OLD = bytes.fromhex("4809f7")     # or rdi, rsi
NEW = bytes.fromhex("83cf01")     # or edi, 1

img = bytearray(open(IMG, "rb").read())
off = SITE - KTEXT
if bytes(img[off:off+3]) != OLD:
    print(f"FAIL: {bytes(img[off:off+3]).hex()}"); sys.exit(1)
img[off:off+3] = NEW
open(IMG, "wb").write(img)
print("OK WP13 fix #17: frequency divisor forced nonzero (or edi,1)")
