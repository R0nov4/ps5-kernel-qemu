#!/usr/bin/env python3
"""WP13 fix #11 — sysinit alloc-object NULL skip (crash 0x9e8e988c, CR2=0x320 WRITE).

Stage fn 0x9e8e9850 (tiny):
    malloc(0x328, ctx 0xA0FEB810, 0x102)  -> NULL (cold boot, fix #5 clean)
    lea rdi, [rax+0x18]                   ; mtx at obj+0x18 = 0x18
    lea rsi, 0x9F65E60E                   ; name
    mov [0xA1933A80], rax                 ; global := NULL
    mtx_init(0x18, ...)                   ; guarded by fix #10 -> clean skip ✓
    mov rax, [0xA1933A80]                 ; NULL
    mov qword ptr [rax+0x320], 0          ; <<< CRASH — write NULL+0x320
    pop rbp; ret

Fix: NULL alloc -> store the NULL global (cold semantics) and return; the
embedded-mtx init and field zeroing are skipped (object doesn't exist).

  site 0x9e8e986a..0x9e8e9874 (11B: lea rdi; lea rsi) -> jmp cave18 + 6 nops
  cave18 @0x9EE30A90 (free gap between cave8-clean-exit and cave9, dead body):
      test rax,rax ; jnz go
      movabs rdx, 0xffffffffa1933a80 ; mov [rdx], rax    ; store NULL
      pop rbp ; ret
    go:
      lea rdi, [rax+0x18] ; movabs rsi, 0xffffffff9f65e60e
      jmp 0x9e8e9875                                        ; normal path
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
CAVE18 = 0x9EE30A90
SPAN = 0x9e8e986a
SPAN_OLD = bytes.fromhex("488d7818" "488d35994dd700")
assert len(SPAN_OLD) == 11

CAVE18_ASM = """
test rax, rax
jnz go
movabs rdx, 0xffffffffa1933a80
mov qword ptr [rdx], rax
pop rbp
ret
go:
lea rdi, qword ptr [rax + 0x18]
movabs rsi, 0xffffffff9f65e60e
jmp 0x9e8e9875
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE18_ASM, CAVE18)
cave18 = bytes(enc)
print(f"cave18: {len(cave18)}B @ {CAVE18:#x}")
assert len(cave18) <= 0x30

img = bytearray(open(IMG, "rb").read())
off = SPAN - KTEXT
if bytes(img[off:off+11]) != SPAN_OLD:
    print(f"FAIL span: {bytes(img[off:off+11]).hex()}"); sys.exit(1)
# sanity: cave18 area must be untouched dead body
print(f"cave18 area old bytes: {bytes(img[CAVE18-KTEXT:CAVE18-KTEXT+8]).hex()}")

rel = CAVE18 - (SPAN + 5)
img[off:off+11] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * 6
off_c = CAVE18 - KTEXT
img[off_c:off_c+len(cave18)] = cave18

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave18 ---")
for i in md.disasm(cave18, CAVE18):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP13 fix #11: NULL sysinit alloc -> store NULL + clean return")
