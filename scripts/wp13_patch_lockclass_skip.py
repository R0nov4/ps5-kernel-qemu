#!/usr/bin/env python3
"""WP13 fix #13 — lock-class node NULL skip (crash 0x9e8b8674, CR2=0x0 WRITE).

Fn 0x9e8b8650 (lock-class/registry node create):
    malloc(0x20, ctx 0x9FEBA2A0, 0x102) -> NULL
    lea rcx, 0x9FE5A540 ; mov rdx, rax
    mov qword ptr [rax], rcx        ; <<< CRASH
    ... [rax+8]=0x800, [rax+0x10]=link, list insert @0x9FEBA290/98 ...
    pop rbp ; jmp 0x9f03b290        ; tail-call register

Fix: NULL -> pop rbp; ret (no node, no list insert, no register call).
  site 0x9e8b866a..0x9e8b8676 (13B) -> jmp cave20 + 8 nops
  cave20 @0x9EE309A0 (dead-body gap after cave19).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
CAVE20 = 0x9EE309A0
SPAN = 0x9e8b866a
SPAN_OLD = bytes.fromhex(
    "488d0dcf1e5a01"   # lea rcx, [rip+0x15a1ecf] -> 0x9fe5a540
    "4889c2"           # mov rdx, rax
    "488908"           # mov [rax], rcx
)
assert len(SPAN_OLD) == 13

CAVE20_ASM = """
test rax, rax
jz null_out
movabs rcx, 0xffffffff9fe5a540
mov rdx, rax
mov qword ptr [rax], rcx
jmp 0x9e8b8677
null_out:
pop rbp
ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE20_ASM, CAVE20)
cave20 = bytes(enc)
print(f"cave20: {len(cave20)}B @ {CAVE20:#x}")

img = bytearray(open(IMG, "rb").read())
off = SPAN - KTEXT
if bytes(img[off:off+13]) != SPAN_OLD:
    print(f"FAIL span: {bytes(img[off:off+13]).hex()}"); sys.exit(1)

rel = CAVE20 - (SPAN + 5)
img[off:off+13] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * 8
off_c = CAVE20 - KTEXT
img[off_c:off_c+len(cave20)] = cave20

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave20 ---")
for i in md.disasm(cave20, CAVE20):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP13 fix #13: NULL lock-class node -> clean return")
