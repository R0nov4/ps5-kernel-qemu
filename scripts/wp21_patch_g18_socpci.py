#!/usr/bin/env python3
"""WP21 G18 — 'Not found soc pci bridge' PANIC -> THE FN'S OWN DESIGNED EXIT
          (a known blocker between done=1006 and 'Device configuration
           finished.' — the user's WP21 cheat-sheet family)

ROOT CAUSE: the SoC-PCI init fn 0x9e8b0f90 probes the bridge by (vendor,
device) id pairs:

      0x9e8b0fe8  call 0x9e6efcf0(0x1022, 0x13df)     ; pci id lookup #1
      0x9e8b0ff0  jne 0x9e8b100a                       ; found -> continue
      0x9e8b0ffc  call 0x9e6efcf0(0x1022, 0x13e4)     ; pci id lookup #2
      0x9e8b1004  je  0x9e8b11b9                       ; <<< both missed -> panic
                                                                ('Not found soc pci bridge')
The fn ALREADY HAS the designed failure exit for its OTHER error path
(the contigmalloc failure at 0x9e8b0fb7 -> 0x9e8b1088: 'mov r14d, 0xc'
-> jmp 0x9e8b1174 'mov eax, r14d; <pops>; ret' = return ENOMEM 12).

FIX — THE LOCAL GUARD: retarget the panic branch to that same designed
exit — 'bridge not found' becomes the fn's own error-12 skip. 6-byte
disp32 retarget, no cave needed.
"""
import sys

KTEXT = 0x9E3F0000
IMG = "./wp21_kit/wp3_boot/kernel_raw.bin"

S = 0x9E8B1004
OLD = bytes.fromhex("0f84af010000")            # je 0x9e8b11b9 (panic block)
NEW = bytes.fromhex("0f847e000000")            # je 0x9e8b1088 (mov r14d,0xc; jmp epilogue)

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

off = S - KTEXT
site = bytes(img[off:off+len(OLD)])
if site == NEW:
    print(f"site {S:#x} already patched (idempotent) — OK"); sys.exit(0)
if site != OLD:
    print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)

# sanity: the retargeted branch must land exactly on the designed exit
assert S + 6 + int.from_bytes(NEW[2:6], "little", signed=True) == 0x9E8B1088

img[off:off+len(NEW)] = NEW
open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP21-G18: 'Not found soc pci bridge' panic -> the fn's own "
      f"designed error-12 exit @0x{S:X}")
