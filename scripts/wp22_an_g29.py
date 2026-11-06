#!/usr/bin/env python3
"""WP22 G29 — static analysis of the REAL-MACHINE crash:
   Fatal trap 12 @0xffffffff9ecce3a0, CR2=0xffffc66300000000 (READ)
   (right after '[MP1] Create rlc dump'; va in ELF = 0xffffffff80aee3a0)

Goal: find the function containing the faulting IP, understand the
self-map read, locate the entry + callers, and design the guard.
"""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./wp22_kit/wp3_boot/kernel_raw.bin"

img = open(IMG, "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

IP = 0xFFFFFFFF9ECCE3A0
off = (IP & 0xFFFFFFFF) - KTEXT

# --- 1. disassemble a window around the faulting IP ---
WIN_BACK, WIN_FWD = 0x180, 0x200
start = off - WIN_BACK
code = img[start:off + WIN_FWD]
base = KTEXT + start
print(f"=== window around IP {IP:#x} (file off {off:#x}) ===")
for i in md.disasm(code, base):
    mark = " <<< FAULT IP" if i.address == IP else ""
    print(f"  {i.address:#x}  {i.bytes.hex():<30} {i.mnemonic} {i.op_str}{mark}")
