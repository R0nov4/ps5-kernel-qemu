#!/usr/bin/env python3
"""WP16 #18 — witness chain NULL guard (crash 0x9e81dee3 CR2=0x40 R).

ROOT CAUSE: the same lock-bookkeeping family as WP16#17 — the mtx slow
  path's witness chain walks [rdi+0x40] with rdi = NULL (the witness
  tables never initialized): 'mov rcx,[rdi+0x40]; test; je 0x9e81df0c'
  — the designed empty-continuation exists, but rdi itself is NULL.

FIX — cave60 @0x9E401700 replacing [0x9e81dee3, 0x9e81deec) (9B:
  'mov rcx,[rdi+0x40]; test rcx,rcx; je 0x9e81df0c'):
    rdi == 0 -> jump straight to the designed empty continuation
    0x9e81df0c; else replay the mov+test and return to 0x9e81deec.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE60 = 0x9E401700
S60, S60E = 0x9E81DEE3, 0x9E81DEEC          # mov rcx,[rdi+0x40]; test; je (9B)
SKIP_TO = 0xFFFFFFFF9E81DF0C

OLD60 = bytes.fromhex("488b4f404885c97420")

C60 = f"""
    test rdi, rdi
    jz   empty
    mov  rcx, qword ptr [rdi + 0x40]
    test rcx, rcx
    jz   empty
    jmp  {0xFFFFFFFF9E81DEEC:#x}
empty:
    jmp  {SKIP_TO:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C60, CAVE60)
print(f"cave60: {len(code):#x}B @ {CAVE60:#x}  hook {S60:#x} ({len(OLD60)}B)")
assert len(code) <= 0x80, "cave60 too big"

img = bytearray(open(IMG, "rb").read())

off = S60 - KTEXT
site = bytes(img[off:off+len(OLD60)])
if site[:1] == b"\xe9":
    rel_expect = CAVE60 - (S60 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S60:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S60:#x}: already hooked to cave60 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD60:
        print(f"FAIL site {S60:#x}: {site.hex()} (expected {OLD60.hex()})"); sys.exit(1)
    hooked = False

off = CAVE60 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave {CAVE60:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

md = Cs(CS_ARCH_X86, CS_MODE_64)
insns = list(md.disasm(code, CAVE60))

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE60 - (S60 + 5)
    off = S60 - KTEXT
    img[off:off+len(OLD60)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD60) - 5)

print("--- cave60 ---")
for i in insns:
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP16#18: witness chain NULL guard (cave60)")
