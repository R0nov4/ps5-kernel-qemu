#!/usr/bin/env python3
"""Pass 1c: instruction-aligned verification of VMMCALL + custom MSR sites.
Method: for each raw byte hit, try linear disassembly from every start offset
in [hit-24, hit]; if any sweep yields an instruction boundary EXACTLY at the
hit address, the site is a genuine instruction. Print verified contexts."""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DUMP = "./ps5/dump13/kernel-13.60-live.bin"
TEXT_SIZE = 13_369_344
TEXT_BASE = 0xFFFFFFFF9E3F0000

blob = open(DUMP, "rb").read()
text = blob[:TEXT_SIZE]
md = Cs(CS_ARCH_X86, CS_MODE_64)

def is_real_site(h):
    """Check if byte at offset h begins an instruction in some aligned sweep."""
    for back in range(0, 25):
        s = h - back
        if s < 0: break
        pos = s
        ok = False
        for _ in range(64):
            if pos == h:
                ok = True; break
            if pos > h: break
            ins = next(md.disasm(text[pos:pos+16], TEXT_BASE + pos), None)
            if ins is None: break
            pos += ins.size
        if ok:
            # decode the actual instruction at h
            ins = next(md.disasm(text[h:h+16], TEXT_BASE + h), None)
            return True, back, ins
    return False, None, None

# --- VMMCALL verification ---
hits, i = [], text.find(b"\x0f\x01\xd9")
while i != -1:
    hits.append(i); i = text.find(b"\x0f\x01\xd9", i + 1)
print(f"raw 0F01D9 hits: {len(hits)}")
verified = []
for h in hits:
    ok, back, ins = is_real_site(h)
    tag = "REAL" if ok else "FALSE"
    mn = f"{ins.mnemonic} {ins.op_str}" if ins else "?"
    print(f"  0x{TEXT_BASE+h:016x}  {tag:5s}  -> {mn}")
    if ok:
        verified.append((h, back, ins))
print(f"\nVERIFIED VMMCALL instructions: {len(verified)}/{len(hits)}")

print("\n=== aligned context for verified sites ===")
for h, back, ins in verified:
    s = h - max(back, 24)
    print(f"\n-- 0x{TEXT_BASE+h:x} (aligned, back={back}) --")
    pos = s
    count = 0
    lines = []
    while pos < h + 24 and count < 14:
        i2 = next(md.disasm(text[pos:pos+16], TEXT_BASE + pos), None)
        if i2 is None: break
        marker = ">>>" if pos == h else "   "
        lines.append(f"  {marker} 0x{i2.address:x}  {i2.mnemonic} {i2.op_str}")
        pos += i2.size
        count += 1
    print("\n".join(lines))

# --- MSR family verification (the x51 uniform family 0xC0000110-117) ---
import struct
print("\n=== MSR 0xC0000110-0xC0000117 family: aligned verification of first 16 sites ===")
fam_sites = []
i = 0
while True:
    i = text.find(b"\xb9", i)
    if i == -1 or i + 5 > len(text): break
    imm = struct.unpack_from("<I", text, i + 1)[0]
    if 0xC0000110 <= imm <= 0xC0000117:
        fam_sites.append((i, imm))
    i += 1
real = 0
for h, imm in fam_sites[:16]:
    ok, back, ins = is_real_site(h)
    real += ok
    if ok and real <= 4:
        s = h - max(back, 20)
        pos, lines = s, []
        while pos < h + 20:
            i2 = next(md.disasm(text[pos:pos+16], TEXT_BASE + pos), None)
            if i2 is None: break
            marker = ">>>" if pos == h else "   "
            lines.append(f"  {marker} 0x{i2.address:x}  {i2.mnemonic} {i2.op_str}")
            pos += i2.size
        print(f"\n-- mov ecx,0x{imm:X} @ 0x{TEXT_BASE+h:x} (REAL) --")
        print("\n".join(lines[:10]))
print(f"\nMSR-family verified (first 16 sampled): {real}/16")

# --- the head-of-text boot code (GDT loading!) ---
print("\n=== text head disasm (0xffffffff9e3f0000, boot/locore-like) ===")
pos, count = 0, 0
while count < 45:
    ins = next(md.disasm(text[pos:pos+16], TEXT_BASE + pos), None)
    if ins is None: break
    print(f"  0x{ins.address:x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}")
    pos += ins.size
    count += 1
