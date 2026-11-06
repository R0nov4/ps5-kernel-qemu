#!/usr/bin/env python3
"""Pass 1b: text-region density profile + VMMCALL context disassembly."""
import struct, math
from collections import Counter
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DUMP = "./ps5/dump13/kernel-13.60-live.bin"
TEXT_SIZE, DATA_OFF, DATA_SIZE = 13_369_344, 0xCC0000, 90_177_536
TEXT_BASE, DATA_BASE = 0xFFFFFFFF9E3F0000, 0xFFFFFFFF9F0B0000

blob = open(DUMP, "rb").read()
text, data = blob[:TEXT_SIZE], blob[DATA_OFF:]

def hexdump(b, base, n=128):
    for i in range(0, min(n, len(b)), 16):
        row = b[i:i+16]
        hx = " ".join(f"{x:02x}" for x in row)
        asc = "".join(chr(x) if 32 <= x < 127 else "." for x in row)
        print(f"  {base+i:012x}  {hx:<48}  |{asc}|")

print("=== text head (first 128 bytes) ===")
hexdump(text, TEXT_BASE)
print("\n=== around offset 0x1000 ===")
hexdump(text[0x1000:0x1000+64], TEXT_BASE+0x1000, 64)
print("\n=== around first VMMCALL cluster (0x2bb6c9) ===")
hexdump(text[0x2bb680:0x2bb680+96], TEXT_BASE+0x2bb680, 96)

# per-64KB density/entropy profile
print("\n=== 64KB-block profile of text (nonzero%% + entropy) — first 40 blocks ===")
CH = 65536
for k in range(0, min(40, TEXT_SIZE // CH)):
    blk = text[k*CH:(k+1)*CH]
    nz = sum(1 for x in blk if x)
    c = Counter(blk)
    H = -sum(v/len(blk)*math.log2(v/len(blk)) for v in c.values())
    bar = "#" * int(nz/len(blk)*40)
    print(f"  off 0x{k*CH:07X} va 0x{TEXT_BASE+k*CH:X} nz={nz/len(blk)*100:5.1f}% H={H:5.3f} {bar}")
# find where dense code starts
first_dense = None
for k in range(TEXT_SIZE // CH):
    blk = text[k*CH:(k+1)*CH]
    nz = sum(1 for x in blk if x)
    if nz / len(blk) > 0.5:
        first_dense = k; break
print(f"\nfirst >50% dense 64KB block: idx {first_dense} -> offset 0x{first_dense*CH:X} va 0x{TEXT_BASE+first_dense*CH:X}")

# VMMCALL disassembly context
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False
hits, i = [], text.find(b"\x0f\x01\xd9")
while i != -1:
    hits.append(i); i = text.find(b"\x0f\x01\xd9", i+1)
print(f"\n=== VMMCALL disasm context ({len(hits)} sites) ===")
# cluster sites
shown = 0
for h in hits:
    # disassemble from 64 bytes before, skipping until we land on the vmmcall
    start = max(0, h - 64)
    insns = list(md.disasm(text[start:h+16], TEXT_BASE + start))
    # find the vmmcall instruction
    pre = []
    for ins in insns:
        if ins.address == TEXT_BASE + h:
            pre.append(ins)
            break
        pre.append(ins)
    # print last 6 instructions before + vmmcall + 3 after
    tail = [f"{ins.mnemonic} {ins.op_str}" for ins in pre[-7:]]
    after = list(md.disasm(text[h+3:h+32], TEXT_BASE + h + 3))
    tail += [f">>> {ins.mnemonic} {ins.op_str}" for ins in after[:3]]
    print(f"\n  -- site va 0x{TEXT_BASE+h:x} --")
    for t in tail:
        print(f"     {t}")
    shown += 1
    if shown >= 14: break

# look for hypercall number loading before vmmcall: mov eax/ecx/edi, imm
print("\n=== immediates near VMMCALL sites (hypercall numbers?) ===")
for h in hits:
    window = text[max(0,h-48):h]
    for reg, hi in (("eax", 0xB8), ("ecx", 0xB9), ("edx", 0xBA), ("ebx", 0xBB),
                    ("esi", 0xBE), ("edi", 0xBF)):
        pat = bytes([hi])
        j = window.find(pat)
        while j != -1:
            if j+5 <= len(window):
                imm = struct.unpack_from("<I", window, j+1)[0]
                if imm < 0x1000:
                    print(f"  site 0x{TEXT_BASE+h:x}: mov {reg}, 0x{imm:x}")
            j = window.find(pat, j+1)
