#!/usr/bin/env python3
"""xref.py — find all RIP-relative code references to given VAs in kernel .text,
plus absolute 64-bit data pointers in the data segment.
Usage: python3 xref.py <hexva> [<hexva> ...]
"""
import sys, struct
import capstone

ELF = "./download/ps5_kernel_1360_reconstructed.elf"
T_VA, T_OFF, T_SZ = 0x9E3F0000, 0x1000, 0xCC0000
D_VA, D_OFF, D_SZ = 0x9F0B0000, 0xCC1000, 0x3174000

blob = open(ELF, "rb").read()
text = blob[T_OFF:T_OFF+T_SZ]
data = blob[D_OFF:D_OFF+D_SZ]

targets = [int(a, 16) for a in sys.argv[1:]]
tset = set(targets)

# ---- pass 1: raw disp32 scan (candidates; verified in pass 2) ----
cands = {t: [] for t in targets}
n = len(text)
for i in range(n - 4):
    disp = struct.unpack_from("<i", text, i)[0]
    rip = T_VA + i + 4
    tgt = (rip + disp) & 0xFFFFFFFFFFFFFFFF
    if tgt in tset:
        cands[tgt].append(i)

# ---- pass 2: disassemble ±32B windows around candidates to confirm ----
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
confirmed = {t: [] for t in targets}
for t, offs in cands.items():
    for i in offs:
        lo = max(0, i - 24)
        hi = min(n, i + 24)
        for off in range(lo, hi):
            for ins in md.disasm(text[off:hi], T_VA + off):
                if ins.address > T_VA + i:
                    break
                end = ins.address + ins.size
                if T_VA + i < end and T_VA + i >= ins.address and \
                   ("rip" in ins.op_str or "eip" in ins.op_str):
                    # the disp32 at i lies inside this rip-relative insn
                    if ins.address <= T_VA + i < end:
                        confirmed[t].append((ins.address, ins.mnemonic + " " + ins.op_str))
                    break

# ---- data xrefs: absolute 8-byte pointers ----
data_hits = {t: [] for t in targets}
for t in targets:
    pat = struct.pack("<Q", 0xFFFFFFFF00000000 | t)
    start = 0
    while True:
        j = data.find(pat, start)
        if j < 0: break
        data_hits[t].append(D_VA + j)
        start = j + 1

for t in targets:
    print(f"\n=== xrefs to {t:#x} ===")
    seen = set()
    for addr, txt in confirmed[t]:
        if addr not in seen:
            seen.add(addr)
            print(f"  CODE {addr:#x}: {txt}")
    if data_hits[t]:
        print(f"  DATA ptrs at: {[hex(a) for a in data_hits[t]]}")
    if not confirmed[t] and not data_hits[t]:
        print("  (none)")
