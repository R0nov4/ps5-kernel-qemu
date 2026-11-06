#!/usr/bin/env python3
"""WP3-4a v4: root-cause the three REAL bugs.
B1: strlen(0xc09) — find caller of 0x9ec227a0 (strlen clone)
B2: stale DMAP console struct — read fmt strings, find structure context
B3: pcpu[0x20]=0 — read pcpu template, check stub code
"""
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
def cstr(va, maxlen=100):
    b = rd(va, maxlen)
    if b is None: return None
    z = b.find(b"\x00"); s = b[:z if z >= 0 else maxlen]
    return s if all(32 <= c < 127 for c in s) else None
md = Cs(CS_ARCH_X86, CS_MODE_64)
def dis(va, back, fwd, mark=None):
    for i in md.disasm(rd(va - back, back + fwd), va - back):
        m = "   <<<<" if mark and i.address == mark else ""
        print(f"  {i.address:#x}: {i.bytes.hex():22s} {i.mnemonic:9s} {i.op_str}{m}")

print("=== strings ===")
for va in [0x9F6E8550, 0x9F6CDA95, 0x9F67B8EA]:
    print(f"  {va:#x}: {cstr(va)!r}")

print("\n=== B2: function 0x9ee30ca0 (the printf+port-IO fn) fmt ===")
dis(0x9EE30CA0, 0, 0x50)
# rip after lea = 0x9ee30cb4; fmt = +0x8b789c
fmt_va = 0x9EE30CB4 + 0x8B789C
print(f"  fmt string @ {fmt_va:#x}: {cstr(fmt_va)!r}")

print("\n=== B1: XREF callers of strlen-clone 0x9ec227a0 ===")
text = img[:0xCC0000]
base = 0x9E3F0000
targets = set()
for i in range(len(text) - 5):
    if text[i] == 0xE8:  # call rel32
        rel = struct.unpack("<i", text[i+1:i+5])[0]
        tgt = base + i + 5 + rel
        if tgt == 0x9EC227A0:
            targets.add(base + i)
    if text[i] == 0xE9:  # jmp rel32
        rel = struct.unpack("<i", text[i+1:i+5])[0]
        tgt = base + i + 5 + rel
        if tgt == 0x9EC227A0:
            targets.add(base + i)
print(f"  callers: {[hex(t) for t in sorted(targets)]}")
for t in sorted(targets):
    print(f"\n  --- caller context at {t:#x}:")
    dis(t, 0x50, 0x18, mark=t)

print("\n=== B3: pcpu template 0x9fe5a080 first 0x40 bytes ===")
b = rd(0x9FE5A080, 0x40)
for i in range(0, 0x40, 8):
    print(f"  +{i:#04x}: {struct.unpack('<Q', b[i:i+8])[0]:#018x}")

print("\n=== B3b: full #GP stub 0x9e6446c0 ===")
dis(0x9E6446C0, 0, 0x1B0)

print("\n=== B2b: .data context around stale-ptr slot 0xa1fdf3c0 ===")
b = rd(0xA1FDF380, 0x90)
for i in range(0, 0x90, 8):
    va = 0xA1FDF380 + i
    v = struct.unpack("<Q", b[i:i+8])[0]
    note = "  <-- stale DMAP(0x1974000)" if va == 0xA1FDF3C0 else ""
    print(f"  {va:#x}: {v:#018x}{note}")
print("\n=== B2c: .data around 0x9fe84160 (stale DMAP(0x17e6f80)) ===")
b = rd(0x9FE84120, 0x80)
for i in range(0, 0x80, 8):
    va = 0x9FE84120 + i
    v = struct.unpack("<Q", b[i:i+8])[0]
    note = "  <-- stale DMAP(0x17e6f80)" if va == 0x9FE84160 else ""
    print(f"  {va:#x}: {v:#018x}{note}")
