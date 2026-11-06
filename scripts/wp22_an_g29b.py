#!/usr/bin/env python3
"""WP22 G29 part 2 — the recursive-slot installer function at 0x9eccbf00-ish.
Compare pristine vs patched (WP21 image) to understand the pmap-gate patches."""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
PATCHED = "./wp22_kit/wp3_boot/kernel_raw.bin"
PRISTINE = "./wp22_kit/pristine/kernel_raw.bin"

md = Cs(CS_ARCH_X86, CS_MODE_64)

cur = open(PATCHED, "rb").read()
pris = open(PRISTINE, "rb").read()

# find function start: scan back from 0x9eccc000 for prologue/int3 padding
start_va = 0x9ECCBF00
off = start_va - KTEXT

print("=== PRISTINE [0x9eccbf00, 0x9eccc0c0) ===")
for i in md.disasm(pris[off:off + 0xC0], start_va):
    print(f"  {i.address:#x}  {i.bytes.hex():<28} {i.mnemonic} {i.op_str}")
print()
print("=== PATCHED (WP21) [0x9eccbf00, 0x9eccc0c0) ===")
for i in md.disasm(cur[off:off + 0xC0], start_va):
    print(f"  {i.address:#x}  {i.bytes.hex():<28} {i.mnemonic} {i.op_str}")
