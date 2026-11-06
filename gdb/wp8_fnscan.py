#!/usr/bin/env python3
"""WP8 fnscan — find function entries containing given addresses.
Strategy: scan backwards for [padding run][55 48 89 e5] (push rbp; mov rbp,rsp)
or [c3/ret][55 48 89 e5]; verify by disassembling forward to the target."""
import sys
sys.path.insert(0, "./scripts")
import capstone

DUMP = "./ps5/dump13/kernel-13.60-live.bin"
KTEXT = 0xFFFFFFFF9E3F0000
IMG = open(DUMP, "rb").read()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = False

def find_entry(target, maxback=0x3000):
    off = target - KTEXT
    # walk backwards; candidate = position of '55 48 89 e5'
    best = None
    lo = max(0, off - maxback)
    i = off - 4
    cands = []
    while i >= lo:
        if IMG[i:i+4] == b"\x55\x48\x89\xe5":
            # check preceding padding/ret
            prev = IMG[i-1]
            prev2 = IMG[i-2]
            if prev in (0x90, 0xC3, 0xCC) or prev2 in (0x90, 0xC3, 0xCC) \
               or IMG[i-5:i] in (b"\x90"*5,):
                cands.append(i)
        i -= 1
    # verify: disassemble from candidate; must reach target cleanly
    for c in reversed(cands):  # closest first
        code = IMG[c:off + 16]
        va = KTEXT + c
        ok = False
        for ins in md.disasm(code, va):
            if ins.address + ins.size > target:
                ok = ins.address <= target < ins.address + ins.size
                break
        if ok:
            return KTEXT + c
    return None

targets = [int(x, 16) for x in sys.argv[1:]]
for t in targets:
    e = find_entry(t)
    print(f"addr {t:#x} -> fn entry {('#%x' % e) if e else 'NOT FOUND'}")
