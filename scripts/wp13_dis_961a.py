#!/usr/bin/env python3
"""WP13 — disasm crash site 0x9e82961a (CR2=0x40) from the REAL image."""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
img = open(IMG, "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

print("=== crash window 0x9e8295c0..0x9e829680 ===")
off = 0x9e8295c0 - KTEXT
for i in md.disasm(img[off:off+0xc0], 0x9e8295c0):
    mark = "   <<< CRASH" if i.address == 0x9e82961a else ""
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}{mark}")

# find function start (nop pad + push rbp)
print("\n=== function start scan ===")
off = 0x9e82961a - KTEXT
for b in range(off, off - 0x800, -1):
    if img[b] == 0x55 and img[b-1] == 0x90 and img[b-2] == 0x90:
        print(f"fn start: {b + KTEXT:#x}")
        o = b
        for i in md.disasm(img[o:o+0x70], b + KTEXT):
            print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
        break
