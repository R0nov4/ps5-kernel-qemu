#!/usr/bin/env python3
"""WP24 G42 pass3 — exact load contexts + aligned caller windows."""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
img = open("wp3_boot/kernel_raw.bin", "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

def dis(va, n, maxn=40):
    out = []
    for i in md.disasm(img[va - KTEXT:va - KTEXT + n], va):
        out.append(i)
        if len(out) >= maxn:
            break
    return out

def show(ins):
    for i in ins:
        print(f"  {i.address:#x}: {i.bytes.hex():<20} {i.mnemonic} {i.op_str}")

for load in (0x9e82d26a, 0x9e82e069, 0x9e82e139):
    print(f"== load ctx {load:#x} ==")
    show(dis(load, 0x1c, maxn=8))
    print()

print("== fn 0x9e82e130 full ==")
show(dis(0x9e82e130, 0x60, maxn=22))
print()

for cs in (0x9e6b5f6b, 0x9e93dc1f, 0x9e952527):
    base = None
    for back in range(0x20, 0x400):
        if img[cs - back - KTEXT:cs - back - KTEXT + 4] == b"\x55\x48\x89\xe5":
            cand = cs - back
            ins = dis(cand, cs - cand + 0x8, maxn=200)
            if any(i.address == cs for i in ins):
                base = cand
                break
    print(f"== caller {cs:#x} (fn {base and hex(base)}) ==")
    if base:
        for i in dis(base, cs - base + 0x40, maxn=220):
            if cs - 0x24 <= i.address <= cs + 0x2c:
                mark = "  <<< call d710" if i.address == cs else ""
                print(f"  {i.address:#x}: {i.bytes.hex():<20} {i.mnemonic} {i.op_str}{mark}")
    print()
