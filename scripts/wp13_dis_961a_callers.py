#!/usr/bin/env python3
"""WP13 — find callers of 0x9e829610 + the NULL global source."""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
img = open(IMG, "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

target = 0x9e829610
print("=== direct callers of 0x9e829610 ===")
o = 0x9E780000 - KTEXT
end = 0x9F100000 - KTEXT
callers = []
while o < end - 5:
    if img[o] == 0xe8:
        rel = int.from_bytes(img[o+1:o+5], "little", signed=True)
        if o + KTEXT + 5 + rel == target:
            callers.append(o + KTEXT)
    o += 1
print(f"callers: {[hex(c) for c in callers]}")

for c in callers:
    print(f"\n=== context before caller {c:#x} (back 0x30) ===")
    off = c - KTEXT - 0x30
    va = c - 0x30
    for i in md.disasm(img[off:off+0x40], va):
        print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
    # rip-relative target resolution
    off2 = c - KTEXT - 0x30
    for i in md.disasm(img[off2:off2+0x40], va):
        for op in i.operands:
            if op.type == 3 and op.mem.base == 41:
                ea = i.address + i.size + op.mem.disp
                print(f"    ^ {i.address:#x} -> global {ea:#x} (value: {int.from_bytes(img[ea-KTEXT:ea-KTEXT+8], 'little'):#x})")
