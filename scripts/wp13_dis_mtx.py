#!/usr/bin/env python3
"""WP13 — disasm mtx_lock slow path from the REAL (patched) image."""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
img = open(IMG, "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

print("=== mtx_lock 0x9e8b6a00 fast path + slow path (REAL image) ===")
off = 0x9e8b6a00 - KTEXT
for i in md.disasm(img[off:off+0x60], 0x9e8b6a00):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

print("\n=== slow path 0x9e8b6a5d .. 0x9e8b6cd0 ===")
off = 0x9e8b6a5d - KTEXT
for i in md.disasm(img[off:off+0x90], 0x9e8b6a5d):
    mark = "   <<< CRASH 0x9e8b6c71" if i.address == 0x9e8b6c71 else ""
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}{mark}")

print("\n=== adaptive spin window 0x9e8b6c50..0x9e8b6ca0 ===")
off = 0x9e8b6c50 - KTEXT
for i in md.disasm(img[off:off+0x50], 0x9e8b6c50):
    mark = "   <<< CRASH" if i.address == 0x9e8b6c71 else ""
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}{mark}")
