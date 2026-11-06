#!/usr/bin/env python3
"""WP22 G29 part 4 — who writes/reads the PML4-page global 0xA1F37E60,
   and where does pmap load CR3 (0f 22 / 0f 20 patterns) in the pmap region."""
import numpy as np
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./wp22_kit/wp3_boot/kernel_raw.bin"
img = open(IMG, "rb").read()
n = len(img)
md = Cs(CS_ARCH_X86, CS_MODE_64)

views = []
for s in range(4):
    cnt = (n - s) // 4
    views.append(np.frombuffer(img, dtype="<u4", count=cnt, offset=s).astype(np.int64))

def rip_xrefs(target):
    C = (target - KTEXT - 4) & 0xFFFFFFFF
    hits = []
    for s in range(4):
        v = views[s]
        idx = np.where((v + (np.arange(len(v), dtype=np.int64) * 4 + s)) & 0xFFFFFFFF == C)[0]
        for i in idx:
            hits.append(s + 4 * i)
    return sorted(hits)

def show(p, back=14, fwd=34):
    start = max(0, p - back)
    for i in md.disasm(img[start:start + fwd + 20], KTEXT + start):
        mark = " <<<<" if i.address <= KTEXT + p < i.address + i.size else ""
        print(f"    {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}{mark}")
        if i.address > KTEXT + p + 16:
            break

print("=== rip-relative xrefs to PML4-page global 0xA1F37E60 ===")
for p in rip_xrefs(0xA1F37E60):
    print(f"  hit file+{p:#x} VA {KTEXT+p:#x}:")
    show(p)

print()
print("=== mov cr3 / mov r?,cr3 sites in [0x9eccb000, 0x9ecd0000) ===")
region = img[0x9eccb000 - KTEXT: 0x9ecd0000 - KTEXT]
for i in md.disasm(region, 0x9eccb000):
    if "cr3" in i.op_str:
        print(f"  {i.address:#x}  {i.bytes.hex():<20} {i.mnemonic} {i.op_str}")
