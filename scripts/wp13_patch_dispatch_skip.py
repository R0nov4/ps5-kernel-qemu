#!/usr/bin/env python3
"""WP13 fix #12 — create-and-dispatch NULL-object skip (crash 0x9eb2dd7a, CR2=0x28).

Fn 0x9eb2dd40 (create object + dispatch):
    malloc(0x30, ctx 0xA05F5F10, 0x102) -> NULL (cold boot)
    mov ecx,[rbp-0x2c]
    mov [rax+0x28], r12        ; <<< CRASH — write NULL+0x28
    mov [rax+0x18], r14 ; mov rdi,rbx ; mov rsi,r13 ; mov rdx,rax
    mov [rax+0x10], ecx ; mov [rax+0x20], r15
    <epilogue> jmp 0x9eb2ddb0  ; tail-call dispatch(rbx, r13, obj)

Fix: NULL alloc -> clean return NULL (no field writes, no dispatch).
  site 0x9eb2dd77..0x9eb2dd91 (27B) -> jmp cave19 + 22 nops
  cave19 @0x9EE30940 (free dead-body gap 0x9EE30915..0x9EE309FF):
      test rax,rax ; jz null_out ; <replay all 8 insns> ; jmp 0x9eb2dd92
    null_out: add rsp,8; pop rbx..r15; pop rbp; ret   (returns rax = NULL)
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
CAVE19 = 0x9EE30940
SPAN = 0x9eb2dd77
SPAN_OLD = bytes.fromhex(
    "8b4dd4"      # mov ecx,[rbp-0x2c]
    "4c896028"    # mov [rax+0x28], r12
    "4c897018"    # mov [rax+0x18], r14
    "4889df"      # mov rdi, rbx
    "4c89ee"      # mov rsi, r13
    "4889c2"      # mov rdx, rax
    "894810"      # mov [rax+0x10], ecx
    "4c897820"    # mov [rax+0x20], r15
)
assert len(SPAN_OLD) == 27

CAVE19_ASM = """
test rax, rax
jz null_out
mov ecx, dword ptr [rbp - 0x2c]
mov qword ptr [rax + 0x28], r12
mov qword ptr [rax + 0x18], r14
mov rdi, rbx
mov rsi, r13
mov rdx, rax
mov dword ptr [rax + 0x10], ecx
mov qword ptr [rax + 0x20], r15
jmp 0x9eb2dd92
null_out:
add rsp, 8
pop rbx
pop r12
pop r13
pop r14
pop r15
pop rbp
ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE19_ASM, CAVE19)
cave19 = bytes(enc)
print(f"cave19: {len(cave19)}B @ {CAVE19:#x}")
assert len(cave19) <= 0xC0

img = bytearray(open(IMG, "rb").read())
off = SPAN - KTEXT
if bytes(img[off:off+27]) != SPAN_OLD:
    print(f"FAIL span: {bytes(img[off:off+27]).hex()}"); sys.exit(1)
print(f"cave19 area old bytes: {bytes(img[CAVE19-KTEXT:CAVE19-KTEXT+8]).hex()}")

rel = CAVE19 - (SPAN + 5)
img[off:off+27] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * 22
off_c = CAVE19 - KTEXT
img[off_c:off_c+len(cave19)] = cave19

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave19 (head) ---")
for i in md.disasm(cave19, CAVE19):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP13 fix #12: NULL object -> clean return NULL")
