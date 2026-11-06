#!/usr/bin/env python3
"""Resolve the frozen-timer: thunk 0x9e659c08 -> target fn -> what does it read?"""
import struct
import capstone

ELF = "./download/ps5_kernel_1360_reconstructed.elf"
T_VA, T_OFF, T_SZ = 0x9E3F0000, 0x1000, 0xCC0000
D_VA, D_OFF, D_SZ = 0x9F0B0000, 0xCC1000, 0x3174000
blob = open(ELF, "rb").read()
def img(va, n):
    lo = va & 0xFFFFFFFF
    if 0x9E3F0000 <= lo < 0x9F0B0000:
        o = lo - 0x9E3F0000; return blob[T_OFF+o:T_OFF+o+n]
    if 0x9F0B0000 <= lo < 0xA2224000:
        o = 0xCC0000 + (lo - 0x9F0B0000); return blob[D_OFF+o:D_OFF+o+n]
    raise ValueError(hex(va))
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
def dis(va, n, label=""):
    print(f"--- {label} {va:#x} ---")
    for i in md.disasm(img(va, n), va):
        ann = ""
        # rip-relative
        if "rip" in i.op_str:
            import re
            m = re.search(r"rip ([+-]) (0x[0-9a-f]+)", i.op_str)
            if m:
                tgt = i.address + i.size + (int(m.group(2),16) if m.group(1)=='+' else -int(m.group(2),16))
                ann = f"   ; -> {tgt:#x}"
        print(f"  {i.address:#x}: {i.bytes.hex():<20} {i.mnemonic} {i.op_str}{ann}")

# 1. resolve thunk 0x9e659c08
b = img(0x9E659C08, 8)
print(f"thunk @ 0x9e659c08: {b.hex()}")
assert b[0] == 0xE9
rel = struct.unpack("<i", b[1:5])[0]
target = 0x9E659C08 + 5 + rel
print(f"  jmp rel32 = {rel} -> target {target:#x}")

# 2. disassemble target fn (timer read!)
dis(target - 0x40, 0xC0, "timer fn")

# 3. also resolve the putchar thunk 0x9e65c4b8 for reference
b2 = img(0x9E65C4B8, 8)
if b2[0] == 0xE9:
    rel2 = struct.unpack("<i", b2[1:5])[0]
    print(f"\nputchar thunk 0x9e65c4b8 -> {0x9E65C4B8+5+rel2:#x}")

# 4. callers from the stack
dis(0x9EBE0DB0, 0x60, "caller frame1 (ret 0x9ebe0de7)")
dis(0x9E7DEB70, 0x70, "caller frame2 (ret 0x9e7debbc)")

# 5. strings
for va in (0x9F6CDD9B, 0x9F6CDA95, 0x9FEB43D0):
    try:
        s = img(va, 60).split(b"\0",1)[0]
        print(f"string {va:#x}: {s!r}")
    except Exception as e:
        print(f"string {va:#x}: ERR")
