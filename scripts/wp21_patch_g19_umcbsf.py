#!/usr/bin/env python3
"""WP21 G19 — 'UMC: BSF(0:0:0) is not found' PANIC -> THE FN'S CLEAN EPILOGUE
          (a known blocker between done=1006 and 'Device configuration
           finished.' — the user's WP21 cheat-sheet family)

ROOT CAUSE: the UMC init fn 0x9ed70980 starts by resolving the memory
controller device at BSF(0:0:0):

      0x9ed70991  call 0x9e6efc50(0, 0, 0)        ; device lookup BSF 0:0:0
      0x9ed7099d  test rax, rax
      0x9ed709a0  je   0x9ed70caa                  ; <<< NULL -> panic
                                                    ('UMC: BSF(0:0:0) is not found' + ud2)
No UMC controller exists in the VM, so the lookup answers the designed
NULL and the init dies before doing any of its MMIO window setup.

FIX — THE LOCAL GUARD: retarget the panic branch to the fn's own clean
epilogue at 0x9ed70ca1 ('pop rbx; pop r12; pop r14; pop r15; pop rbp;
ret' — the pops exactly balance the prologue, no stack sub). The UMC
stage becomes the designed skip; the return value is the NULL rax=0,
which its sysinit caller ignores. 6-byte disp32 retarget.
"""
import sys

KTEXT = 0x9E3F0000
IMG = "./wp21_kit/wp3_boot/kernel_raw.bin"

S = 0x9ED709A0
OLD = bytes.fromhex("0f8404030000")            # je 0x9ed70caa (panic block)
NEW = bytes.fromhex("0f84fb020000")            # je 0x9ed70ca1 (the clean pop-epilogue)

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

off = S - KTEXT
site = bytes(img[off:off+len(OLD)])
if site == NEW:
    print(f"site {S:#x} already patched (idempotent) — OK"); sys.exit(0)
if site != OLD:
    print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)

assert S + 6 + int.from_bytes(NEW[2:6], "little", signed=True) == 0x9ED70CA1

img[off:off+len(NEW)] = NEW
open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP21-G19: 'UMC: BSF(0:0:0) is not found' panic -> the fn's "
      f"own clean epilogue @0x{S:X}")
