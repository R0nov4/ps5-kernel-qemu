#!/usr/bin/env python3
"""Pass 1d: FIXED verifier (back>=1) + full hypercall wrapper-table extraction.
Sony HV ABI: wrappers are 'mov eax, <nr>; vmmcall' -> extract complete number set."""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DUMP = "./ps5/dump13/kernel-13.60-live.bin"
TEXT_SIZE = 13_369_344
TEXT_BASE = 0xFFFFFFFF9E3F0000
blob = open(DUMP, "rb").read()
text = blob[:TEXT_SIZE]
md = Cs(CS_ARCH_X86, CS_MODE_64)

def is_real(h, want_mnemonic=None):
    for back in range(1, 33):
        s = h - back
        if s < 0: break
        pos = s
        for _ in range(48):
            if pos == h:
                ins = next(md.disasm(text[h:h+16], TEXT_BASE + h), None)
                if ins is None: return False, None
                if want_mnemonic and ins.mnemonic != want_mnemonic:
                    return False, None
                return True, back
            if pos > h: break
            i2 = next(md.disasm(text[pos:pos+16], TEXT_BASE + pos), None)
            if i2 is None: break
            pos += i2.size
    return False, None

# ---- fixed VMMCALL verification ----
hits, i = [], text.find(b"\x0f\x01\xd9")
while i != -1:
    hits.append(i); i = text.find(b"\x0f\x01\xd9", i+1)
real, false = [], []
for h in hits:
    ok, back = is_real(h, "vmmcall")
    (real if ok else false).append(h)
print(f"VMMCALL raw={len(hits)}  REAL={len(real)}  FALSE={len(false)}")
for h in false:
    print(f"  false-positive @ 0x{TEXT_BASE+h:x}")

# ---- extract hypercall numbers: 'mov eax, imm32; vmmcall' (B8 imm32 0F01D9) ----
pats = []
i = 0
while True:
    i = text.find(b"\xb8", i)
    if i == -1 or i + 8 > len(text): break
    if text[i+5:i+8] == b"\x0f\x01\xd9":
        imm = struct.unpack_from("<I", text, i+1)[0]
        ok, back = is_real(i, "mov")  # mov eax, imm is real instruction?
        if ok:
            pats.append((i, imm))
    i += 1
print(f"\n'mov eax,imm; vmmcall' wrapper sites: {len(pats)}")
nrs = {}
for off, imm in pats:
    nrs.setdefault(imm, []).append(off)
print(f"unique hypercall numbers: {len(nrs)}")
print("\n=== SONY HV HYPERCALL NUMBER TABLE (from kernel 13.60) ===")
for imm in sorted(nrs):
    addrs = ", ".join(f"0x{TEXT_BASE+o:x}" for o in nrs[imm][:3])
    extra = f" (+{len(nrs[imm])-1} more)" if len(nrs[imm]) > 3 else ""
    print(f"  hypercall {imm:4d} (0x{imm:x}): {addrs}{extra}")

# ---- wrapper-table region boundaries ----
if pats:
    lo = min(o for o, _ in pats); hi = max(o for o, _ in pats)
    print(f"\nwrapper region: 0x{TEXT_BASE+lo:x} .. 0x{TEXT_BASE+hi:x} ({hi-lo+8} bytes)")

# ---- disassemble the full wrapper region nicely (first 120 insns) ----
print("\n=== wrapper region linear disasm (start) ===")
if pats:
    start = min(o for o, _ in pats) - 0x20
    pos, count = start, 0
    while count < 90:
        ins = next(md.disasm(text[pos:pos+16], TEXT_BASE + pos), None)
        if ins is None: break
        print(f"  0x{ins.address:x}  {ins.mnemonic} {ins.op_str}")
        pos += ins.size; count += 1
