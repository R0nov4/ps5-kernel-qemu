#!/usr/bin/env python3
"""wp9_xref.py — find rip-relative LEA references to a target VA in .text."""
import sys, struct

DUMP = "./ps5/dump13/kernel-13.60-live.bin"
KTEXT = 0xffffffff9e3f0000
DATA_FOFF = 0xCC0000
IMG = open(DUMP, "rb").read()

def find_lea_refs(target):
    """scan for 48/4C 8D /r with rip-rel32 resolving to target"""
    res = []
    t = target & 0xffffffffffffffff
    for i in range(0, DATA_FOFF - 7):
        b0 = IMG[i]
        if b0 not in (0x48, 0x4C):
            continue
        if IMG[i+1] != 0x8D:
            continue
        modrm = IMG[i+2]
        if (modrm & 0xC7) != 0x05:  # mod=00, rm=101 (rip-rel)
            continue
        rel = struct.unpack_from("<i", IMG, i+3)[0]
        site = KTEXT + i
        if (site + 7 + rel) & 0xffffffffffffffff == t:
            reg = ((modrm >> 3) & 7) + (8 if b0 == 0x4C else 0)
            res.append((site, reg))
    return res

def find_abs_movs(target):
    """scan for 48 B8+r movabs or 48 C7 / imm32 forms with the value"""
    res = []
    pat8 = struct.pack("<Q", target)
    start = 0
    while True:
        i = IMG.find(pat8, start, DATA_FOFF)
        if i < 0: break
        res.append((KTEXT + i, "movabs/imm64"))
        start = i + 1
    return res

if __name__ == "__main__":
    for arg in sys.argv[1:]:
        t = int(arg, 0)
        print(f"=== refs to {t:#x} ===")
        for site, reg in find_lea_refs(t):
            print(f"  lea r{reg}, rip+.. @ {site:#x}   (img off {site-KTEXT:#x})")
        for site, kind in find_abs_movs(t):
            print(f"  {kind} @ {site:#x}   (img off {site-KTEXT:#x})")
