#!/usr/bin/env python3
"""WP13 fix #16 — linker-file processor NULL guard (crash 0x9e9431e9, CR2=0x0).

Fn 0x9e9431c0 (linker-file symbol processor, rdi = linker_file):
    0x9e9431e9  mov rcx, [rdi]   ; <<< CRASH — rdi = NULL kernel linker_file
Called with [0xA197A3C8] = NULL (fix #14 skip semantics).

Fix: entry guard (cave21 @0x9EE309E0, dead-body gap after cave20):
    test rdi,rdi ; jz null_ret
    replay full 17-byte prologue ; jmp 0x9e9431d1
    null_ret: ret
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
CAVE21 = 0x9EE309E0
ENTRY = 0x9e9431c0
ENTRY_OLD = bytes.fromhex("554889e541")          # push rbp; mov rbp,rsp; [41]57
PROLOGUE = bytes.fromhex("554889e5415741564155415453 4883ec18".replace(" ", ""))
assert len(PROLOGUE) == 17, len(PROLOGUE)

CAVE21_ASM = """
test rdi, rdi
jz null_ret
push rbp
mov rbp, rsp
push r15
push r14
push r13
push r12
push rbx
sub rsp, 0x18
jmp 0x9e9431d1
null_ret:
ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE21_ASM, CAVE21)
cave21 = bytes(enc)
print(f"cave21: {len(cave21)}B @ {CAVE21:#x}")
assert len(cave21) <= 0x20

img = bytearray(open(IMG, "rb").read())
off = ENTRY - KTEXT
if bytes(img[off:off+5]) != ENTRY_OLD:
    print(f"FAIL entry: {bytes(img[off:off+5]).hex()}"); sys.exit(1)
if bytes(img[off:off+17]) != PROLOGUE:
    print(f"FAIL prologue: {bytes(img[off:off+17]).hex()}"); sys.exit(1)

rel = CAVE21 - (ENTRY + 5)
img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)
off_c = CAVE21 - KTEXT
img[off_c:off_c+len(cave21)] = cave21

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave21 ---")
for i in md.disasm(cave21, CAVE21):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP13 fix #16: NULL linker_file -> clean return")
