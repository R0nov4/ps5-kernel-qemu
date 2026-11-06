#!/usr/bin/env python3
"""WP2 STEP 1c (v2) — numpy brute-force scan for RIP-relative refs to contract globals.
Method: for each byte offset p, treat blob[p:p+4] as signed disp32;
rip anchor = va(p)+4; candidate target = anchor + disp. Filter targets,
then verify instruction (modrm rm=101 mod=00) with capstone back-sweep.
"""
import sys, struct
sys.path.insert(0, "./scripts")
import wp1_lib as L
import numpy as np
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

TARGETS = {
    0xFFFFFFFFA1FA55C0: "physfree_bytes(0x22225000)",
    0xFFFFFFFFA1FA55C8: "raw_[0x9bf4c]",
    0xFFFFFFFFA1FA55D0: "raw_[0x9bf54]_(0x1e1e0000)",
    0xFFFFFFFFA1FA55D8: "raw_[0x9b6f4]",
    0xFFFFFFFFA1E251C0: "physmem-ish_(0x22270)",
    0xFFFFFFFFA1FDEF00: "gb_offset_(0x1fe)",
    0xFFFFFFFFA1978CD0: "virtual_avail",
    0xFFFFFFFFA1FA54E0: "dpcpu_sz_(0x4000)",
    0xFFFFFFFFA1FA54D0: "kstack_bytes_(0x4000)",
    0xFFFFFFFFA1FA54E8: "ram_gt_32g",
    0xFFFFFFFFA1FA55A0: "mi_0x42000",
    0xFFFFFFFFA1FA55B8: "mi_1",
    0xFFFFFFFFA1928B20: "reloc_off_tbl_(0x23cef80)",
}

md = Cs(CS_ARCH_X86, CS_MODE_64)

code_start_off = L.va2off(L.CODE_BASE)
blob = L._blob[code_start_off:L.TEXT_SIZE]
base = L.CODE_BASE
n = len(blob)

hits = []
tgt_off = {t - base: t for t in TARGETS}          # work in offset space (all positive int64)
toff_arr = np.array(sorted(tgt_off), dtype=np.int64)
for a in range(4):
    m = (n - a) // 4
    arr = np.frombuffer(blob, dtype="<u4", count=m, offset=a).astype(np.int64)
    # signed
    arr = np.where(arr >= 0x80000000, arr - 0x100000000, arr)
    pos = np.arange(m, dtype=np.int64) * 4 + a          # offset in blob
    anchor = pos + 4                                    # rip anchor (offset space)
    tgt = anchor + arr
    mask = np.isin(tgt, toff_arr)
    for k in np.nonzero(mask)[0]:
        p = int(pos[k])
        hits.append((base + p, tgt_off[int(tgt[k])]))

print(f"{len(hits)} raw disp32 candidates")
# verify: modrm byte at p-1 with mod=00 rm=101 (or rex+modrm)
MODRM = {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}
verified = []
for va_disp, tgt in hits:
    p = va_disp - base
    b1 = blob[p-1]
    ok = b1 in MODRM
    if not ok and p >= 2 and 0x40 <= blob[p-2] <= 0x4F:
        ok = True   # REX + modrm
    if not ok:
        continue
    # capstone: find instruction ending exactly at va_disp+4
    for back in range(1, 18):
        s = p - back
        if s < 0:
            break
        got = None
        for ins in md.disasm(blob[s:p+4], base + s):
            if ins.address + ins.size == va_disp + 4:
                got = ins
                break
        if got is not None:
            f, _ = L.containing_function(va_disp)
            verified.append((va_disp, tgt, got.mnemonic, got.op_str, f))
            break

print(f"{len(verified)} verified instructions:\n")
for va, tgt, m, o, f in sorted(verified):
    print(f"  0x{va:x}  {m} {o}   -> 0x{tgt:x} ({TARGETS[tgt]})  [fn 0x{f:x}]")
