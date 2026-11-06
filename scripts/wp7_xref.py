#!/usr/bin/env python3
"""wp7_xref.py — full .text rip-relative xref scan for msgbuf-related globals.

Targets:
  msgbufp        0xffffffffa1fb8a60
  msgbufsize     0xffffffffa1d103e0 (dword)
  msgbufp2       0xffffffffa1926620
  msgbuf flag    0xffffffffa1926628 (byte)
Linear-sweeps .text with capstone, collects every rip-relative ref.
"""
import capstone, re, sys

DUMP = "./ps5/dump13/kernel-13.60-live.bin"
KTEXT = 0xffffffff9e3f0000
DATA_FOFF = 0xCC0000
TEXT_END = 0xffffffff9f0b0000

TARGETS = {
    0xffffffffa1fb8a60: "msgbufp",
    0xffffffffa1d103e0: "msgbufsize(dword)",
    0xffffffffa1926620: "msgbufp2",
    0xffffffffa1926628: "msgbuf_flag(byte)",
    # neighbors of msgbufsize (params block)
    0xffffffffa1d103e8: "param_0x80000000_1",
    0xffffffffa1d103f0: "param_0x80000000_2",
    0xffffffffa1d103f8: "param_32GB",
    0xffffffffa1d10400: "param_8MB",
    0xffffffffa1d10408: "param_2MB",
}

with open(DUMP, "rb") as f:
    img = f.read()
text = img[:DATA_FOFF]

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

refs = []
# chunked linear sweep (code is dense; linear sweep is what previous wp scripts used)
CH = 0x100000
for base in range(0, len(text), CH):
    chunk = text[base:base+CH]
    for ins in md.disasm(chunk, KTEXT + base):
        if "[rip " in ins.op_str:
            m = re.search(r"\[rip ([+-]) (0x[0-9a-f]+)\]", ins.op_str)
            if m:
                sign = 1 if m.group(1) == "+" else -1
                tgt = ins.address + ins.size + sign * int(m.group(2), 16)
                if tgt in TARGETS:
                    refs.append((ins.address, ins.mnemonic, ins.op_str, TARGETS[tgt]))

print(f"total refs: {len(refs)}")
for addr, mn, ops, name in refs:
    print(f"{addr:#018x}  {mn:8s} {ops:44s} -> {name} @ {name}")
