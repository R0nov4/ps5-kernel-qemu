#!/usr/bin/env python3
"""WP2 STEP 2d — classify readers/writers of the top boolean globals.
For each candidate: find all instruction sites (disp32 sweep), classify as
WRITE (mov [rip],imm / mov [rip],reg) or READ, and show the writing function's
strings (identification hints).
"""
import sys, struct
sys.path.insert(0, "./scripts")
import wp1_lib as L
import numpy as np
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

CANDS = [
    0xFFFFFFFFA0FF95B0, 0xFFFFFFFFA0FF95C8, 0xFFFFFFFFA1E36DE8, 0xFFFFFFFFA1F99668,
    0xFFFFFFFFA1F9A470, 0xFFFFFFFFA19276D8, 0xFFFFFFFFA1F9E000, 0xFFFFFFFFA1DB91F8,
    0xFFFFFFFFA1F72728, 0xFFFFFFFFA1E24F28, 0xFFFFFFFFA1152020, 0xFFFFFFFFA0950040,
]

md = Cs(CS_ARCH_X86, CS_MODE_64)
code_start_off = L.va2off(L.CODE_BASE)
blob = L._blob[code_start_off:L.TEXT_SIZE]
base = L.CODE_BASE
n = len(blob)

for tgt in CANDS:
    toff = tgt - base
    sites = []
    for a in range(4):
        m = (n - a) // 4
        arr = np.frombuffer(blob, dtype="<u4", count=m, offset=a).astype(np.int64)
        arr = np.where(arr >= 0x80000000, arr - 0x100000000, arr)
        pos = np.arange(m, dtype=np.int64) * 4 + a
        t = pos + 4 + arr
        mask = (t == toff)
        for k in np.nonzero(mask)[0]:
            sites.append(int(pos[k]))
    # classify each site
    writes, reads = [], []
    for p in sites:
        for back in range(1, 16):
            s = p - back
            if s < 0:
                break
            got = None
            for ins in md.disasm(blob[s:p+8], base + s):
                if ins.address + ins.size == base + p + 4:
                    got = ins
                    break
            if got is not None:
                kind = "W" if (got.mnemonic == "mov" and "[" in got.op_str.split(",")[0]) else ("R" if got.mnemonic in ("cmp","test","mov","lea","movzx","movsx","add","sub","and","or","xor","push","imul","inc","dec") else got.mnemonic)
                entry = (got.address, got.mnemonic, got.op_str)
                (writes if kind == "W" else reads).append(entry)
                break
    print("=" * 104)
    print(f"TARGET 0x{tgt:x}  live_u32={L.read_u32(tgt)}  sites={len(sites)}  writes={len(writes)}")
    for va, mn, op in writes[:12]:
        f, _ = L.containing_function(va)
        strs = [s for _, _, s in L.function_strings(f, f + 0x200)][:3]
        print(f"   WRITE @0x{va:x}: {mn} {op}   [fn 0x{f:x}] {' | '.join(strs)}")
    if len(writes) > 12:
        print(f"   ... {len(writes)-12} more writes")
