#!/usr/bin/env python3
"""scan .text for rip-relative refs to a target VA (lea/mov)"""
import sys, capstone

DUMP = "./ps5/dump13/kernel-13.60-live.bin"
KTEXT = 0xffffffff9e3f0000
DATA_FOFF = 0xCC0000
TARGET = int(sys.argv[1], 0)

img = open(DUMP, "rb").read()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

hits = []
text = img[:DATA_FOFF]
# brute: decode windows at each 16-byte grid would be slow; instead scan for
# lea/mov rip patterns: 48 8d 0d/05/15/35/3d <rel32> etc. decode candidate positions
import struct
for i in range(len(text) - 7):
    b = text[i]
    if b in (0x48, 0x4c) and text[i+1] == 0x8d and (text[i+2] & 0xC7) == 0x05:
        rel = struct.unpack_from("<i", text, i+3)[0]
        va = KTEXT + i
        tgt = va + 7 + rel
        if tgt == TARGET:
            hits.append((va, "lea", text[i:i+7].hex()))
    if b in (0x48, 0x4c) and text[i+1] == 0x8b and (text[i+2] & 0xC7) == 0x05:
        rel = struct.unpack_from("<i", text, i+3)[0]
        va = KTEXT + i
        tgt = va + 7 + rel
        if tgt == TARGET:
            hits.append((va, "mov", text[i:i+7].hex()))
for va, kind, hx in hits:
    print(f"{kind} @ {va:#x}  bytes {hx}")
print(f"total: {len(hits)}")
