#!/usr/bin/env python3
"""WP3-4a v5: identify the ORIGINAL printf (event 0) via fmt string + kvprintf strlen site + boot-stack residue."""
import struct
from capstone import *
img = open("./wp3_boot/kernel_raw.bin", "rb").read()
def va2img(va):
    lo = va & 0xFFFFFFFF
    if 0x9E3F0000 <= lo < 0x9F0B0000: return lo - 0x9E3F0000
    if 0x9F0B0000 <= lo < 0xA2224000: return 0xCC0000 + (lo - 0x9F0B0000)
    return None
def rd(va, n):
    o = va2img(va); return None if o is None else img[o:o+n]
def showstr(va, n=0x80):
    b = rd(va, n)
    z = b.find(b"\x00")
    s = b[:z if z >= 0 else n]
    print(f"  {va:#x}: {s!r}")
    return s
md = Cs(CS_ARCH_X86, CS_MODE_64)
def dis(va, back, fwd, mark=None):
    for i in md.disasm(rd(va - back, back + fwd), va - back):
        m = "   <<<< return addr (R10)" if mark and i.address == mark else ""
        print(f"  {i.address:#x}: {i.bytes.hex():22s} {i.mnemonic:9s} {i.op_str}{m}")

print("=== 1. RAW fmt string candidates (event-0 RBX=0x9f67b8ea) ===")
showstr(0x9F67B8EA)
# also scan back for the string start (maybe mid-string)
for off in (-0x30, -0x20, -0x10):
    showstr(0x9F67B8EA + off)

print("\n=== 2. kvprintf strlen site: disasm around R10=0x9e89f525 ===")
dis(0x9E89F525, 0x60, 0x10, mark=0x9E89F525)

print("\n=== 3. boot-stack live residue [0xa1130980..0xa1130a60] ===")
b = rd(0xA1130980, 0xE0)
for i in range(0, 0xE0, 8):
    va = 0xA1130980 + i
    v = struct.unpack("<Q", b[i:i+8])[0]
    tag = ""
    if 0xFFFFFFFF9E000000 <= v < 0xFFFFFFFFA0000000: tag = f"  -> .text (0x{v:#x})"
    elif 0xFFFFFFFFA0000000 <= v < 0xFFFFFFFFA3000000: tag = f"  -> .data"
    note = "   <-- RSP/RBP (retaddr @ -8 = 0xa11309d8)" if va == 0xA11309E0 else ""
    if va == 0xA11309D8: tag = f"  <-- RETADDR SLOT: 0x{v:#x}" + (f" (.text!)" if 0xFFFFFFFF9E000000 <= v < 0xFFFFFFFFA0000000 else "")
    if va == 0xA1130A20: tag = f"  <-- R14/R15 value target"
    print(f"  {va:#x}: {v:#018x}{tag}{note}")

print("\n=== 4. what the LIVE boot stack at 0xa1130a20 held ===")
b = rd(0xA1130A00, 0x40)
for i in range(0, 0x40, 8):
    print(f"  {0xA1130A00+i:#x}: {struct.unpack('<Q', b[i:i+8])[0]:#018x}")
