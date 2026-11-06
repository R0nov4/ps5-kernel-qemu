#!/usr/bin/env python3
"""WP15 #16 — swap-helper NULL-old guard (crash 0x9e8b7cb6, CR2=0x8).

ROOT CAUSE: the atomic-swap helper 0x9e8b7c90 stores the new value and
then PROCESSES the old one:
    0x9e8b7c9a  mov rax, [rdi]         ; old (return)
    0x9e8b7c9d  mov rbx, [rdi]         ; old (processed)
    0x9e8b7ca0  mov [rdi], rsi         ; store new
    ...
    0x9e8b7cb6  test byte ptr [rbx + 8], 0x40   <<< CRASH (old==NULL)
    0x9e8b7cbc  mov eax, [rbx + 0xc]   ; recursion count
    ... [rbx + 0x18] := 4 (mark the old lock free) ...
  The per-CPU slot held NULL (never initialized) -> the 'old' processing
  dereferences NULL.

FIX: cave37 @0x9E400B80 replacing [0x9e8b7cb6, 0x9e8b7cbc):
    rbx == 0 -> jump to the function's own plain exit 0x9e8b7cf1
    (add rsp,8; pop rbx; pop r14; pop r15; pop rbp; ret) — the swap
    itself already happened; there is simply no old object to process.
    else -> replay 'test byte [rbx+8], 0x40' + the original jne.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE37  = 0x9E400B80
SITE    = 0x9E8B7CB6
EXIT_F  = 0xFFFFFFFF9E8B7CF1       # plain exit (pops + ret)
JNE_F   = 0xFFFFFFFF9E8B7D2C       # original jne target
CONT_F  = 0xFFFFFFFF9E8B7CBC       # fall-through

SITE_OLD = bytes.fromhex("f643084075 70".replace(" ", ""))   # test byte [rbx+8],0x40 ; jne (6B)

CAVE37_ASM = f"""
    test rbx, rbx
    jnz  go
    jmp  {EXIT_F:#x}
go:
    test byte ptr [rbx + 8], 0x40
    jne  {JNE_F:#x}
    jmp  {CONT_F:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE37_ASM, CAVE37)
if not enc:
    print("ASM FAILED"); sys.exit(1)
cave37 = bytes(enc)
print(f"cave37: {len(cave37):#x}B @ {CAVE37:#x}")
assert len(cave37) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = SITE - KTEXT
if bytes(img[off:off+len(SITE_OLD)]) != SITE_OLD:
    print(f"FAIL site {SITE:#x}: {bytes(img[off:off+len(SITE_OLD)]).hex()} != {SITE_OLD.hex()}")
    sys.exit(1)
off = CAVE37 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave37 {CAVE37:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

rel = CAVE37 - (SITE + 5)
off = SITE - KTEXT
img[off:off+len(SITE_OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(SITE_OLD) - 5)

off = CAVE37 - KTEXT
img[off:off+len(cave37)] = cave37

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave37 ---")
for i in md.disasm(cave37, CAVE37):
    print(f"  {i.address:#x}  {i.bytes.hex():<16} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP15#16: swap-helper NULL-old guard (cave37 @0x9E400B80)")
