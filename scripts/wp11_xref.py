#!/usr/bin/env python3
"""WP11 — xref scan (light): regex-based rip-relative + imm scan over .text.
Targets: seed allocator statics + queue registry slots."""
import re
import struct
import capstone
import time

DUMP = "./ps5/dump13/kernel-13.60-live.bin"
KTEXT = 0x9E3F0000
TEXT_OFF_END = 0xCC0000
CHUNK = 0x100000

TARGETS = {
    0xA1CF3F10: "W4-bitmap",
    0xA093E6A0: "W6-listtail",
    0xA18EA8F8: "qreg-8f8",
    0xA18EA828: "qreg-828",
    0xA18EA840: "qreg-840",
    0xA093E6A0: "W6-listtail",
}

img = open(DUMP, "rb").read()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

RIP_P = re.compile(r"\[rip \+ (0x[0-9a-f]+)\]")
RIP_M = re.compile(r"\[rip - (0x[0-9a-f]+)\]")

t0 = time.time()
hits = []
off = 0
while off < TEXT_OFF_END:
    chunk = img[off:off + CHUNK + 0x100]
    for ins in md.disasm(chunk, KTEXT + off):
        if ins.address >= KTEXT + off + CHUNK:
            break
        m = RIP_P.search(ins.op_str)
        m2 = RIP_M.search(ins.op_str)
        if m:
            tgt = ins.address + ins.size + int(m.group(1), 16)
            if tgt in TARGETS:
                hits.append((ins.address, ins.mnemonic, ins.op_str, TARGETS[tgt]))
        elif m2:
            tgt = ins.address + ins.size - int(m2.group(1), 16)
            if tgt in TARGETS:
                hits.append((ins.address, ins.mnemonic, ins.op_str, TARGETS[tgt]))
    off += CHUNK

print(f"sweep done in {time.time()-t0:.1f}s — {len(hits)} refs\n")
for addr, m, ops, name in hits:
    print(f"{addr:#018x}  {m} {ops:44s} -> {name}")
