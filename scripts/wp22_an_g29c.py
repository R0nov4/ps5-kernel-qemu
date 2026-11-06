#!/usr/bin/env python3
"""WP22 G29 part 3b — whole-image xref scan, byte-granular numpy (4 shifts)."""
import numpy as np
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./wp22_kit/wp3_boot/kernel_raw.bin"
img = open(IMG, "rb").read()
n = len(img)
arr = np.frombuffer(img, dtype=np.uint8)
md = Cs(CS_ARCH_X86, CS_MODE_64)

# four shifted u4 views: view_s[i] = img[s+4i : s+4i+4]
views = []
for s in range(4):
    cnt = (n - s) // 4
    views.append(np.frombuffer(img, dtype="<u4", count=cnt, offset=s).astype(np.int64))

def rip_xrefs(target):
    """byte positions p with img[p:p+4] as signed disp32 s.t. VA(p)+4+disp == target"""
    C = (target - KTEXT - 4) & 0xFFFFFFFF
    hits = []
    for s in range(4):
        v = views[s]
        idx = np.where((v + (np.arange(len(v), dtype=np.int64) * 4 + s)) & 0xFFFFFFFF == C)[0]
        for i in idx:
            hits.append(s + 4 * i)
    return sorted(hits)

def call_xrefs(target):
    """byte positions p: img[p]==0xe8, rel32(img[p+1:p+5]) + (VA(p)+5) == target"""
    C = (target - KTEXT - 5) & 0xFFFFFFFF
    hits = []
    for s in range(4):
        # rel32 window starts at p+1 → window position q = p+1, s.t. q ≡ s (mod 4)
        v = views[s]
        q_idx = np.arange(len(v), dtype=np.int64) * 4 + s      # window start q
        sel = np.where((v + q_idx + 5) & 0xFFFFFFFF == C)[0]
        for i in sel:
            q = int(q_idx[i])
            p = q - 1
            if p >= 0 and img[p] == 0xE8:
                hits.append(p)
    return sorted(hits)

def show_hit(p, back=12, fwd=30):
    start = max(0, p - back)
    va = KTEXT + start
    code = img[start:start + fwd + 16]
    for i in md.disasm(code, va):
        mark = ""
        if i.address <= KTEXT + p < i.address + i.size:
            mark = "   <<<< XREF"
        print(f"    {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}{mark}")
        if i.address > KTEXT + p + 14:
            break

for name, tgt in [("SELF-MAP SLOT global 0xA1F37E4C", 0xA1F37E4C),
                  ("DMAP-PML4I global 0xA1F39294", 0xA1F39294)]:
    print(f"=== rip-relative xrefs to {name} ===")
    for p in rip_xrefs(tgt):
        print(f"  hit file+{p:#x} VA {KTEXT+p:#x}:")
        show_hit(p)
    print()

for name, tgt in [("kextract 0x9ecce330", 0x9ECCE330),
                  ("RECBASE-getter 0x9eccbf10", 0x9ECCBF10),
                  ("bootstrap-fn 0x9eccbf50", 0x9ECCBF50)]:
    print(f"=== direct e8 calls to {name} ===")
    for p in call_xrefs(tgt):
        print(f"  call at VA {KTEXT+p:#x}")
    print()
