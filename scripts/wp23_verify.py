#!/usr/bin/env python3
"""WP23 static verification — disassemble every WP23 hook/stub/string.

Run from the kit root. ZERO QEMU: this is the static proof that the
G39/G40/G41 patches landed byte-exactly (mirrors the round's method).
"""
import re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"
img = open(IMG, "rb").read()
assert len(img) == 65224704, f"bad size {len(img)}"
md = Cs(CS_ARCH_X86, CS_MODE_64)

def fmt(ins):
    line = f"{ins.address:#x}  {ins.bytes.hex():<24} {ins.mnemonic} {ins.op_str}"
    m = re.search(r"\[rip ([+-]) (0x[0-9a-f]+)\]", ins.op_str)
    if m:
        d = int(m.group(2), 16) * (1 if m.group(1) == "+" else -1)
        line += f"   ; -> {ins.address + ins.size + d:#x}"
    return line

def show(va, nbytes, tag, maxn=60):
    print(f"=== {tag} ===")
    c = 0
    for ins in md.disasm(img[va - KTEXT:va - KTEXT + nbytes], va):
        print(fmt(ins))
        c += 1
        if c >= maxn:
            break

show(0x9E7C3F02, 0x1A, "G39 unpark: restored thunk tail")
show(0x9EB6E9D0, 0x10, "G40 hook site")
show(0x9E404600, 0xC6, "G40 stub @0x9E404600")
show(0x9E92639B, 0x18, "G41 hook site (loop-exit region)")
show(0x9E404700, 0x40, "G41 park stub")
print("msg @0x9E404740:", img[0x9E404740 - KTEXT:].split(b"\x00")[0])
fake = img[0x9E404800 - KTEXT:0x9E404C00 - KTEXT]
print(f"fake block: {len(fake)} bytes, all zero = {all(b == 0 for b in fake)}")
print("image md5 gate: see wp23_build_all.sh [4]")
