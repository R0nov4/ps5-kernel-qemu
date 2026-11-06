#!/usr/bin/env python3
"""WP15 #13 — atomic-swap helper NULL-target guard (crash 0x9e8b7c9a, CR2=0x0).

ROOT CAUSE: the atomic-swap helper 0x9e8b7c90 (used by the per-CPU/AP
table updates in 0x9eaa5xxx/0x9eaa6xxx: 'mov rsi, [idx*0x40 + r12 +
0x48c0]; call' — and the sleepq module 0x9f00a745) does:
    0x9e8b7c9a  mov rax, [rdi]      ; old value      <<< CRASH (rdi==NULL)
    0x9e8b7c9d  mov rbx, [rdi]      ; old value (processed below)
    0x9e8b7ca0  mov [rdi], rsi      ; store the new value
    ... processes the OLD value ([rbx+8], [rbx+0xc], [rbx+0x18] := 4) ...
  A NULL target means the per-CPU slot's object was never created (one of
  the NULL-guarded init paths).

FIX: cave35 @0x9E400A80 — entry guard:
    rdi == 0 -> xor eax, eax ; ret (the designed 'swapped nothing' return;
       no pushes have happened yet, all caller-saved regs intact)
    else -> replay the 10 replaced prologue bytes (push rbp; mov rbp,rsp;
       push r15; push r14; push rbx; push rax) and continue at 0x9e8b7c9a.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE35  = 0x9E400A80
SITE    = 0x9E8B7C90
CONT_F  = 0xFFFFFFFF9E8B7C9A

SITE_OLD = bytes.fromhex("554889e5415741565350")   # 10B prologue

CAVE35_ASM = f"""
    test rdi, rdi
    jnz  go
    xor  eax, eax
    ret
go:
    push rbp
    mov  rbp, rsp
    push r15
    push r14
    push rbx
    push rax
    jmp  {CONT_F:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE35_ASM, CAVE35)
if not enc:
    print("ASM FAILED"); sys.exit(1)
cave35 = bytes(enc)
print(f"cave35: {len(cave35):#x}B @ {CAVE35:#x}")
assert len(cave35) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = SITE - KTEXT
if bytes(img[off:off+len(SITE_OLD)]) != SITE_OLD:
    print(f"FAIL site {SITE:#x}: {bytes(img[off:off+len(SITE_OLD)]).hex()} != {SITE_OLD.hex()}")
    sys.exit(1)
off = CAVE35 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave35 {CAVE35:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

rel = CAVE35 - (SITE + 5)
off = SITE - KTEXT
img[off:off+len(SITE_OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(SITE_OLD) - 5)

off = CAVE35 - KTEXT
img[off:off+len(cave35)] = cave35

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave35 ---")
for i in md.disasm(cave35, CAVE35):
    print(f"  {i.address:#x}  {i.bytes.hex():<16} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP15#13: atomic-swap helper NULL-target guard (cave35 @0x9E400A80)")
