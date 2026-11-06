#!/usr/bin/env python3
"""WP24 G42 pass2 — hook context, epilogues, callers (short output)."""
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

FNS = [
    (0x9e82d260, 0x9e82d26a),
    (0x9e82d440, 0x9e82d44b),
    (0x9e82d710, 0x9e82d71e),
    (0x9e82e060, 0x9e82e069),
    (0x9e82e130, 0x9e82e139),
]
for fn, load in FNS:
    print(f"== fn {fn:#x} load {load:#x} ==")
    show(dis(load - 0x10, 0x24, maxn=10))
    ins = dis(fn, 0x140, maxn=90)
    je = [i for i in ins if i.mnemonic == "je"]
    if je:
        tgt = int(je[0].op_str, 16)
        print(f"  -- je -> {tgt:#x}:")
        show(dis(tgt, 0x20, maxn=7))
    rets = [i for i in ins if i.mnemonic == "ret"]
    if rets and not je:
        r = rets[0].address
        print(f"  -- tail @{r:#x}:")
        show([i for i in ins if r - 0x18 <= i.address <= r][:9])
    print()

print("== callers of 0x9e82d710 ==")
for cs in (0x9e6b5f6b, 0x9e93dc1f, 0x9e952527):
    print(f"-- around call {cs:#x}:")
    show(dis(cs - 0x14, 0x3c, maxn=13))
    print()
