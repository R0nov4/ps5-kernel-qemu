#!/usr/bin/env python3
"""WP3-4a v6: XREF the spin-lock timeout panic string -> find panic fn + lock wrapper.
Also read the FULL panic string and the lock name candidates."""
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
md = Cs(CS_ARCH_X86, CS_MODE_64)
def dis(va, back, fwd, mark=None):
    for i in md.disasm(rd(va - back, back + fwd), va - back):
        m = "   <<<<" if mark and i.address == mark else ""
        print(f"  {i.address:#x}: {i.bytes.hex():22s} {i.mnemonic:9s} {i.op_str}{m}")

print("=== full panic string (scan back from 0x9f67b8ea to string start) ===")
off = va2img(0x9F67B8EA)
start = off
while start > 0 and img[start-1] != 0:
    start -= 1
    if off - start > 0x100: break
s = img[start:img.find(b"\x00", off)]
print(f"  string start VA: {0x9E3F0000 + start if start < 0xCC0000 else 0x9F0B0000 + (start - 0xCC0000):#x}")
print(f"  FULL: {s!r}")

# the fmt is passed to kvprintf; the string START VA:
SVA = (0x9E3F0000 + start) if start < 0xCC0000 else (0x9F0B0000 + (start - 0xCC0000))
print(f"\n=== XREF: lea rip-relative refs to {SVA:#x} in .text ===")
text = img[:0xCC0000]
hits = []
for i in range(len(text) - 7):
    # 48 8d 3d rel32  (lea rdi, [rip+rel])
    if text[i] == 0x48 and text[i+1] == 0x8D and text[i+2] == 0x3D:
        rel = struct.unpack("<i", text[i+3:i+7])[0]
        tgt = 0x9E3F0000 + i + 7 + rel
        if SVA <= tgt <= SVA + 0x10:
            hits.append((0x9E3F0000 + i, tgt))
    # 48 8d 35 rel32  (lea rsi, [rip+rel])
    if text[i] == 0x48 and text[i+1] == 0x8D and text[i+2] == 0x35:
        rel = struct.unpack("<i", text[i+3:i+7])[0]
        tgt = 0x9E3F0000 + i + 7 + rel
        if SVA <= tgt <= SVA + 0x10:
            hits.append((0x9E3F0000 + i, tgt))
print(f"  hits: {[(hex(a), hex(t)) for a, t in hits]}")
for a, t in hits:
    print(f"\n  --- context around lea at {a:#x} (target {t:#x}):")
    dis(a, 0x30, 0x60, mark=a)
