#!/usr/bin/env python3
"""WP16 #19 — witness unlock NULL guard (crash 0x9e81df3d CR2=0x80 R).

ROOT CAUSE: the same witness family — the unlock path's
  'cmp qword [rbx+0x80], 0; je 0x9e81df96' with rbx = the per-thread
  WITNESS object = NULL (never initialized on this boot) -> CR2=0x80.

FIX — cave61 @0x9E401780 replacing [0x9e81df3d, 0x9e81df45) (14B:
  'cmp qword [rbx+0x80],0; je 0x9e81df96'):
    rbx == 0 -> jump to the designed empty continuation 0x9e81df96;
    else replay the cmp (flags!) and return to 0x9e81df45.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE61 = 0x9E401780
S61, S61E = 0x9E81DF3D, 0x9E81DF45          # cmp [rbx+0x80],0; je (14B)
SKIP_TO = 0xFFFFFFFF9E81DF96

OLD61 = bytes.fromhex("4883bb8000000000744f")

C61 = f"""
    test rbx, rbx
    jz   empty
    cmp  qword ptr [rbx + 0x80], 0
    jmp  {0xFFFFFFFF9E81DF45:#x}
empty:
    jmp  {SKIP_TO:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C61, CAVE61)
print(f"cave61: {len(code):#x}B @ {CAVE61:#x}  hook {S61:#x} ({len(OLD61)}B)")
assert len(code) <= 0x80, "cave61 too big"

img = bytearray(open(IMG, "rb").read())

off = S61 - KTEXT
site = bytes(img[off:off+len(OLD61)])
if site[:1] == b"\xe9":
    rel_expect = CAVE61 - (S61 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S61:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S61:#x}: already hooked to cave61 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD61:
        print(f"FAIL site {S61:#x}: {site.hex()} (expected {OLD61.hex()})"); sys.exit(1)
    hooked = False

off = CAVE61 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave {CAVE61:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

md = Cs(CS_ARCH_X86, CS_MODE_64)
insns = list(md.disasm(code, CAVE61))

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE61 - (S61 + 5)
    off = S61 - KTEXT
    img[off:off+len(OLD61)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD61) - 5)

print("--- cave61 ---")
for i in insns:
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP16#19: witness unlock NULL guard (cave61)")
