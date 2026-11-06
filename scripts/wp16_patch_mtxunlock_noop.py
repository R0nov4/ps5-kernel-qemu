#!/usr/bin/env python3
"""WP16 #20 — mtx unlock NULL-lock no-op (crash 0x9e8b753e CR2=0x8 R).

ROOT CAUSE: the arena-extend chain unlocks a NULL lock object — the
  unlock 0x9e8b7520 gets rdi = NULL+0x18 (the lock-word address of a
  NULL lock) -> 'test byte [rdi-0x10], 0x40' reads [0x8] -> CR2=0x8.

FIX — cave62 @0x9E401800 replacing [0x9e8b753e, 0x9e8b7546) (8B:
  'test byte [rdi-0x10],0x40; lea rsi,[rdi-0x18]'):
    rdi < 0x1000 (the NULL-object lock-word) -> the no-op unlock:
    replicate the epilogue (add rsp,8? no — pop rbx/r12/r14/r15/rbp;
    ret — the prologue pushed rbp + 4 regs, no sub) and return;
    else replay both instructions and continue 0x9e8b7546.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE62 = 0x9E401800
S62, S62E = 0x9E8B753E, 0x9E8B7546          # test [rdi-0x10],0x40; lea rsi,[rdi-0x18] (8B)

OLD62 = bytes.fromhex("f647f040488d77e8")

C62 = f"""
    cmp  rdi, 0x1000
    jb   null_unlock
    test byte ptr [rdi - 0x10], 0x40
    lea  rsi, [rdi - 0x18]
    jmp  {0xFFFFFFFF9E8B7546:#x}
null_unlock:
    pop  rbx
    pop  r12
    pop  r14
    pop  r15
    pop  rbp
    ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C62, CAVE62)
print(f"cave62: {len(code):#x}B @ {CAVE62:#x}  hook {S62:#x} ({len(OLD62)}B)")
assert len(code) <= 0x80, "cave62 too big"

img = bytearray(open(IMG, "rb").read())

off = S62 - KTEXT
site = bytes(img[off:off+len(OLD62)])
if site[:1] == b"\xe9":
    rel_expect = CAVE62 - (S62 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S62:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S62:#x}: already hooked to cave62 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD62:
        print(f"FAIL site {S62:#x}: {site.hex()} (expected {OLD62.hex()})"); sys.exit(1)
    hooked = False

off = CAVE62 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave {CAVE62:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

md = Cs(CS_ARCH_X86, CS_MODE_64)
insns = list(md.disasm(code, CAVE62))

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE62 - (S62 + 5)
    off = S62 - KTEXT
    img[off:off+len(OLD62)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD62) - 5)

print("--- cave62 ---")
for i in insns:
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP16#20: mtx unlock NULL no-op (cave62)")
