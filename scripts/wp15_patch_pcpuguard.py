#!/usr/bin/env python3
"""WP15 #11 — pcpu gs:[8] NULL guard (crash 0x9eaa73c2, CR2=0x3c4).

ROOT CAUSE: the per-CPU init loop stores the pcpu's second field
(gs:[8] — curpcb/curpmap-ish) and its +0x3c4 word into a per-CPU array:
    0x9eaa73b1  mov rax, qword ptr gs:[8]
    0x9eaa73ba  mov qword ptr [r14 + r13 + 0x4d30], rax
    0x9eaa73c2  movzx eax, word ptr [rax + 0x3c4]     <<< CRASH (rax==0)
    0x9eaa73c9  mov word ptr [r14 + r13 + 0x4d38], ax
gs:[8] is NULL on our cold boot (the pcpu field was never set — its
initializer is one of the NULL-guarded paths).

FIX: cave33 @0x9E400980 replacing [0x9eaa73b1, 0x9eaa73d2):
    gs:[8] == 0 -> store 0 for BOTH fields (the designed 'absent' value)
    else -> replay the original 4 instructions.
  Continues at 0x9eaa73d2 (mov rbx, gs:[8] — 0 on the guarded path, the
  callers' NULL checks handle it).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE33  = 0x9E400980
SITE    = 0x9EAA73B1
CONT_F  = 0xFFFFFFFF9EAA73D2

SITE_OLD = bytes.fromhex(
    "65488b042508000000"            # mov rax, gs:[8]            (9B)
    "4b89842e304d0000"              # mov [r14+r13+0x4d30], rax  (8B)
    "0fb780c4030000"                # movzx eax, word [rax+0x3c4](7B)
    "664389842e384d0000"            # mov [r14+r13+0x4d38], ax   (9B)
)                                    # total 33B

CAVE33_ASM = f"""
    mov  rax, qword ptr gs:[8]
    test rax, rax
    jnz  ok
    mov  qword ptr [r14 + r13 + 0x4d30], rax
    xor  eax, eax
    mov  word ptr [r14 + r13 + 0x4d38], ax
    jmp  {CONT_F:#x}
ok:
    mov  qword ptr [r14 + r13 + 0x4d30], rax
    movzx eax, word ptr [rax + 0x3c4]
    mov  word ptr [r14 + r13 + 0x4d38], ax
    jmp  {CONT_F:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE33_ASM, CAVE33)
if not enc:
    print("ASM FAILED"); sys.exit(1)
cave33 = bytes(enc)
print(f"cave33: {len(cave33):#x}B @ {CAVE33:#x}")
assert len(cave33) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = SITE - KTEXT
if bytes(img[off:off+len(SITE_OLD)]) != SITE_OLD:
    print(f"FAIL site {SITE:#x}: {bytes(img[off:off+len(SITE_OLD)]).hex()}")
    print(f"  expected: {SITE_OLD.hex()}")
    sys.exit(1)
off = CAVE33 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave33 {CAVE33:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

rel = CAVE33 - (SITE + 5)
off = SITE - KTEXT
img[off:off+len(SITE_OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(SITE_OLD) - 5)

off = CAVE33 - KTEXT
img[off:off+len(cave33)] = cave33

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave33 ---")
for i in md.disasm(cave33, CAVE33):
    print(f"  {i.address:#x}  {i.bytes.hex():<20} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP15#11: pcpu gs:[8] NULL guard (cave33 @0x9E400980)")
