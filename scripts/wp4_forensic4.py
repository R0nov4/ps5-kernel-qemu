#!/usr/bin/env python3
"""WP4 forensic v4 (final micro-pass): CFI pattern census, stub bodies,
CFI table contents, wrmsr census, caller of strlen(0xc09)."""
import struct, re
from collections import Counter
import capstone

ELF = "./download/ps5_kernel_1360_reconstructed.elf"
T_VA, T_OFF, T_SZ = 0x9E3F0000, 0x1000, 0xCC0000
D_VA, D_OFF, D_SZ = 0x9F0B0000, 0xCC1000, 0x3174000
blob = open(ELF, "rb").read()
text = blob[T_OFF:T_OFF+T_SZ]
data = blob[D_OFF:D_OFF+D_SZ]
def va2off(va):
    lo = va & 0xFFFFFFFF
    if 0x9E3F0000 <= lo < 0x9F0B0000: return lo - 0x9E3F0000
    if 0x9F0B0000 <= lo < 0xA2224000: return 0xCC0000 + (lo - 0x9F0B0000)
    raise ValueError(hex(va))
def img(va, n):
    o = va2off(va)
    return (blob[T_OFF+o:T_OFF+o+n] if o < 0xCC0000 else blob[D_OFF+(o-0xCC0000):D_OFF+(o-0xCC0000)+n])
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
def dis(va, n):
    for i in md.disasm(img(va, n), va):
        print(f"  {i.address:#x}: {i.bytes.hex():<20} {i.mnemonic} {i.op_str}")

print("=== 1. stub bodies 0x9e7df490..0x9e7df520 ===")
dis(0x9E7DF490, 0x90)

print("\n=== 2. CFI callee table 0x9e65d140..0x9e65d190 (9 entries end at 0x9e65d180) ===")
b = img(0x9E65D140, 0x50)
for i in range(0, 0x50, 8):
    print(f"  {0x9E65D140+i:#x}: {struct.unpack('<Q', b[i:i+8])[0]:#018x}")
print("--- and 2nd table around 0x9e65a450 (base-72..base) ---")
b = img(0x9E65A408, 0x50)
for i in range(0, 0x50, 8):
    print(f"  {0x9E65A408+i:#x}: {struct.unpack('<Q', b[i:i+8])[0]:#018x}")

print("\n=== 3. CFI check pattern census in .text ===")
# pattern: 48 c1 c8 03 (ror rax,3) 48 83 f8 imm (cmp rax,imm) 77/0f87 (ja)
pat = re.compile(rb"\x48\xc1\xc8\x03\x48\x83\xf8.\x77.")
hits = [m.start() for m in pat.finditer(text)]
print(f"  ror3+cmp+ja(rel8) sites: {len(hits)}")
pat2 = re.compile(rb"\x48\xc1\xc8\x03\x48\x83\xf8.\x0f\x87....", re.S)
hits2 = [m.start() for m in pat2.finditer(text)]
print(f"  ror3+cmp+ja(rel32) sites: {len(hits2)}")
# broader: any 'ror rax,3' — indicates CFI-ish checks
pat3 = re.compile(rb"\x48\xc1\xc8\x03")
hits3 = [m.start() for m in pat3.finditer(text)]
print(f"  total 'ror rax,3' sites: {len(hits3)}")
# verify each hit is preceded by sub rax, reg (48/4c 29)
sub_pre = sum(1 for h in hits3 if text[h-3:h-1] in (b"\x48\x29", b"\x4c\x29"))
print(f"  of which preceded by 'sub rax, reg': {sub_pre}")
# show first 12 addresses
print("  first CFI sites:", [hex(T_VA+h) for h in hits3[:12]])

print("\n=== 4. wrmsr census (0f 30) in .text ===")
wr = [m.start() for m in re.finditer(rb"\x0f\x30", text)]
print(f"  total 0f30 byte-pairs: {len(wr)}")
sony = {0x1DD, 0x1DE, 0x1D9, 0xC0000110, 0xC0000111, 0xC0000112, 0xC0000113,
        0xC0000114, 0xC0000115, 0xC0000116, 0xC0000117, 0xC0000118, 0xC0000120}
confirmed = []
for h in wr:
    # look back up to 24 bytes for mov ecx, imm32 (b9 xx xx xx xx) or movabs rcx
    win = text[max(0,h-24):h]
    m = list(re.finditer(rb"\xb9(....)", win, re.S))
    if m:
        imm = struct.unpack("<I", m[-1].group(1))[0]
        if imm in sony:
            confirmed.append((h, imm))
print(f"  wrmsr with Sony MSR in ECX (mov ecx,imm within 24B): {len(confirmed)}")
for h, imm in confirmed[:20]:
    print(f"    {T_VA+h:#x}: wrmsr (ecx={imm:#x})")
# stub-region wrmsr/rdmsr
sr = [h for h in wr if 0x252C00 <= h < 0x258200]
print(f"  wrmsr inside stub region: {len(sr)}")
rd = [m.start() for m in re.finditer(rb"\x0f\x32", text)]
srr = [h for h in rd if 0x252C00 <= h < 0x258200]
print(f"  rdmsr total: {len(rd)}, inside stub region: {len(srr)}")

print("\n=== 5. or [gs:0x20+0x100],1 pattern census (stub curthread bit) ===")
pat_or = re.compile(rb"\x65\x48\x8b\x3c\x25\x20\x00\x00\x00\x83\x8f\x00\x01\x00\x00\x01")
orph = [m.start() for m in pat_or.finditer(text)]
print(f"  'mov rdi,gs:[0x20]; or [rdi+0x100],1' sites: {len(orph)}")
for h in orph[:60]:
    print(f"    {T_VA+h:#x}  (or at {T_VA+h+9:#x})")
# also just the 'or [rdi+0x100],1' 7-byte op alone
pat_or2 = re.compile(rb"\x83\x8f\x00\x01\x00\x00\x01")
orph2 = [m.start() for m in pat_or2.finditer(text)]
print(f"  bare 'or dword [rdi+0x100],1' sites: {len(orph2)}")

print("\n=== 6. caller of strlen(0xc09): around return-addr 0x9e89f525 ===")
dis(0x9E89F4C0, 0x80)

print("\n=== 7. 2nd dispatcher tail 0x9e7df2a6..0x9e7df2f0 ===")
dis(0x9E7DF2A6, 0x4A)
