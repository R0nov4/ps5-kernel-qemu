#!/usr/bin/env python3
"""WP13 fix #7 — sleep mtxpool NULL-alloc skip (crash 0x9ea668aa, CR2=0x0 WRITE).

Fn 0x9ea66870 = FreeBSD mtx_pool_init for the SLEEP mutex pool:
    malloc(0x1010, ctx 0xA05E11A0, 0x102)  -> NULL (clean, fix #5)
    rbx = rax
    movabs rcx, 0x7f00000080 ; r15d=0x28 ; r14="sleep mtxpool"(0x9F67D506)
    mov [rbx], rcx           ; <<< CRASH — header write to NULL
    mov [rbx+8], 0x39
    loop 64x: mtx_init(0x9e8b7dd0)(rbx+r15, "sleep mtxpool", 0, 0)  r15+=0x20
    mov [0xA1C1AF98], rbx    ; mtx_pool global := NULL (store itself is fine)
    ret

Cold-boot semantics: allocation failed -> the pool stays NULL (the global is
already residue-wiped to 0) and the stage returns cleanly.

Fix: span 0x9ea66893..0x9ea668b4 (34B) -> jmp cave13 + 29 nops.
cave13 @0x9EE30D00:
    test rbx,rbx ; jz 0x9ea668dd          ; skip header+loop, keep NULL store
    replay: movabs rcx / mov r15d / movabs r14 ("sleep mtxpool") /
            mov [rbx],rcx / mov [rbx+8],0x39 ; jmp 0x9ea668c0 (the init loop)
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
CAVE13 = 0x9EE30D00
SPAN = 0x9ea66893
SPAN_OLD = bytes.fromhex(
    "48b9800000007f000000"      # movabs rcx, 0x7f00000080
    "41bf28000000"              # mov r15d, 0x28
    "4c8d355c6cc100"            # lea r14, [rip+0xc16c5c]  -> "sleep mtxpool"
    "48890b"                    # mov [rbx], rcx
    "48c7430839000000"          # mov [rbx+8], 0x39
)
assert len(SPAN_OLD) == 34, len(SPAN_OLD)

CAVE13_ASM = """
test rbx, rbx
jz 0x9ea668dd
movabs rcx, 0x7f00000080
mov r15d, 0x28
movabs r14, 0xffffffff9f67d506
mov qword ptr [rbx], rcx
mov qword ptr [rbx + 8], 0x39
jmp 0x9ea668c0
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE13_ASM, CAVE13)
cave13 = bytes(enc)
print(f"cave13: {len(cave13)}B @ {CAVE13:#x}")

img = bytearray(open(IMG, "rb").read())
off = SPAN - KTEXT
if bytes(img[off:off+34]) != SPAN_OLD:
    print(f"FAIL span: {bytes(img[off:off+34]).hex()}"); sys.exit(1)

rel = CAVE13 - (SPAN + 5)
img[off:off+34] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * 29
off_c = CAVE13 - KTEXT
img[off_c:off_c+len(cave13)] = cave13

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave13 ---")
for i in md.disasm(cave13, CAVE13):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP13 fix #7: NULL sleep-mtxpool -> stage skipped, global stays NULL")
