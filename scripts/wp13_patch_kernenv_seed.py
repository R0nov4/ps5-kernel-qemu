#!/usr/bin/env python3
"""WP13 fix #8 — kern_env array seed page (crash 0x9e86dc22, CR2=0x0 READ).

[0xA191B560] = kern_envp array pointer. The live dump held DMAP(0x1746000)
(below-kernel staging); the TRAMPOLINE zeroes it at boot (patches.inc entry
"phys 0x2191b560 — kern_envp array ptr := 0"), then the env sysinit stage
(fn 0x9e86dff0) mallocs a new array — which returns NULL on cold boot
(fix #5) — and stores NULL back. Every kern_env reader then derefs NULL:
    getenv-ish fn 0x9e86dbe0: mov rcx,[0xA191B560]; mov r14,[rcx] <<< CRASH
23 read/write sites reference [0xA191B560] — guarding them one-by-one is
impractical. Seed-page pattern instead (user-endorsed):

Fix: at the malloc-result store 0x9e86e01b, when rax==NULL store
DMAP(0x3F002000) — a fresh-zero seed page (reserved by the trampoline SMAP
fix, never allocated). array[0] = NULL -> every reader takes its DESIGNED
empty-array path (e.g. 0x9e86dc25 test r14,r14; je -> unlock + return NULL
"not found"). Later slot writes land in valid zero RAM.

  0x9e86e01b (7B store) -> jmp cave15 + 2 nops
  cave15 @0x9EE30E00:
      test rax,rax ; jnz real
      movabs rcx, 0xffff8e773f002000     ; seed page DMAP (rcx is dead: the
      mov [0xA191B560], rcx              ;  next insn is xor ecx,ecx)
      jmp 0x9e86e022
    real:
      movabs rcx, 0xffffffffa191b560
      mov [rcx], rax
      jmp 0x9e86e022

Seed-area ledger: 0x3F000008 list-tail, 0x3F001000 bitmap (~0x200B),
0x3F002000..0x3F004000 kern_env array (NEW, 0x1008B), 0x3F009000 intr#1,
0x3F00A000 mDBG, 0x3F00C/D000 intr#2/3, 0x3F00F000 PD, 0x3F010000+ bump.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
CAVE15 = 0x9EE30E00
SITE = 0x9e86e01b
SITE_OLD = bytes.fromhex("4889053ed50a03")     # mov [rip+0x30ad53e], rax
assert len(SITE_OLD) == 7

CAVE15_ASM = """
test rax, rax
jnz real
movabs rcx, 0xffff8e773f002000
mov qword ptr [rcx], rcx
jmp 0x9e86e022
real:
movabs rcx, 0xffffffffa191b560
mov qword ptr [rcx], rax
jmp 0x9e86e022
"""
# NOTE: the seed store needs [0xA191B560] := DMAP(page), not [rcx] := rcx — fixed below.
CAVE15_ASM = """
test rax, rax
jnz real
movabs rcx, 0xffff8e773f002000
movabs rdx, 0xffffffffa191b560
mov qword ptr [rdx], rcx
jmp 0x9e86e022
real:
movabs rdx, 0xffffffffa191b560
mov qword ptr [rdx], rax
jmp 0x9e86e022
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE15_ASM, CAVE15)
cave15 = bytes(enc)
print(f"cave15: {len(cave15)}B @ {CAVE15:#x}")
assert len(cave15) <= 0x80

img = bytearray(open(IMG, "rb").read())
off = SITE - KTEXT
if bytes(img[off:off+7]) != SITE_OLD:
    print(f"FAIL site: {bytes(img[off:off+7]).hex()}"); sys.exit(1)

rel = CAVE15 - (SITE + 5)
img[off:off+7] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * 2
off_c = CAVE15 - KTEXT
img[off_c:off_c+len(cave15)] = cave15

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- site ---")
for i in md.disasm(bytes(img[off:off+7]), SITE):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
print("--- cave15 ---")
for i in md.disasm(cave15, CAVE15):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP13 fix #8: kern_env array -> fresh-zero seed page on failed malloc")
