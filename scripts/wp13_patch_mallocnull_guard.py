#!/usr/bin/env python3
"""WP13 fix #5 — malloc frontend NULL zone-table guard (crash 0x9eff8c48, CR2=0x8).

Fn 0x9eff8b50 = the kernel malloc front-end (2136 direct callers — must fix
in-function). Args: rdi=size, rsi=ctx(zone), edx=flags.
Small-size path (size <= [0xA21B4B60-threshold], jbe 0x9eff8c12):
    0x9eff8c12  lea rax, [rip+0x31c2847]     ; rax = size-class table 0xA21B4B60
    0x9eff8c19  mov rbx, [r15+0x18]          ; rbx = ctx zone-table — NULL cold
    0x9eff8c1d  mov edi, 0xa
    0x9eff8c22  movzx r14d, byte [r14+rax]   ; size class
    ...
    0x9eff8c48  movzx eax, byte [rbx+8]      ; <<< CRASH (rbx=NULL)
The large path already has the designed failure node:
    0x9eff8d32  xor r14d,r14d ; test r12b,2 ; je/jmp -> 0x9eff8d92
    0x9eff8d92  mov rax,r14 (=0) ; epilogue ; ret      ; malloc returns NULL

Fix: span 0x9eff8c12..0x9eff8c21 (16B) -> jmp cave11 + 11 nops.
cave11 @0x9EE30B80:
    mov rbx,[r15+0x18] ; test rbx,rbx ; jz 0x9eff8d32   ; designed NULL node
    movabs rax, 0xffffffffa21b4b60 ; mov edi,0xa        ; replay
    jmp 0x9eff8c22
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
CAVE11 = 0x9EE30B80
SPAN = 0x9eff8c12
SPAN_OLD = bytes.fromhex("488d0547281c03" "498b5f18" "bf0a000000")
assert len(SPAN_OLD) == 16

CAVE11_ASM = """
mov rbx, qword ptr [r15 + 0x18]
test rbx, rbx
jz 0x9eff8d32
movabs rax, 0xffffffffa21b4b60
mov edi, 0xa
jmp 0x9eff8c22
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE11_ASM, CAVE11)
cave11 = bytes(enc)
print(f"cave11: {len(cave11)}B @ {CAVE11:#x}")
assert len(cave11) <= 0x80

img = bytearray(open(IMG, "rb").read())
off = SPAN - KTEXT
if bytes(img[off:off+16]) != SPAN_OLD:
    print(f"FAIL span: {bytes(img[off:off+16]).hex()}"); sys.exit(1)

rel = CAVE11 - (SPAN + 5)
img[off:off+16] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * 11
off_c = CAVE11 - KTEXT
img[off_c:off_c+len(cave11)] = cave11

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- span ---")
for i in md.disasm(bytes(img[off:off+16]), SPAN):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
print("--- cave11 ---")
for i in md.disasm(cave11, CAVE11):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP13 fix #5: NULL zone-table -> designed malloc-NULL return")
