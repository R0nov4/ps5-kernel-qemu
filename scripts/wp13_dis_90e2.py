#!/usr/bin/env python3
"""WP13 — disasm crash site 0x9eff90e2 (CR2=0x8, WRITE) from the REAL image."""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
img = open(IMG, "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

# find function start
off = 0x9eff90e2 - KTEXT
start = None
for b in range(off, off - 0x1000, -1):
    if img[b] == 0x55 and img[b-1] == 0x90 and img[b-2] == 0x90:
        start = b + KTEXT
        break
print(f"function start: {start and hex(start)}")

if start:
    o = start - KTEXT
    for i in md.disasm(img[o:o+0x140], start):
        mark = "   <<< CRASH" if i.address == 0x9eff90e2 else ""
        print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}{mark}")
