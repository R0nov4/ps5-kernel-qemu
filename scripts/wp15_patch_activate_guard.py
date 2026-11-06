#!/usr/bin/env python3
"""WP15 #17 — pmap-activate NULL-proc guard (crash 0x9ecdcbb1, CR2=0x200).

ROOT CAUSE: the SMP-launch sequence calls 0x9ecdcba0(curthread):
    0x9ecdcba4  mov rax, gs:[0x788]
    0x9ecdcBAD  mov rcx, [rdi + 8]        ; the thread's proc/vmspace obj
    0x9ecdcbb1  mov rsi, [rcx + 0x200]    ; <<< CRASH (rcx==NULL)
    0x9ecdcbb8  lea rcx, [rsi + 0x2e8]
    0x9ecdcbbf  cmp rcx, rax ; ...        ; the activate/CR3 dance
  (caller 0x9eccef24: 'mov rbx, gs:[0]; call 0x9ea92630; rdi = rbx;
   call 0x9ecdcba0' — i.e. activate(curthread) during the AP launch;
   thread0's +8 object is NULL at this stage on our cold boot.)

FIX: cave38 @0x9E400C00 replacing [0x9ecdcBAD, 0x9ecdcbbf) (17B):
    rcx == 0 -> the function's own void exit (pop rbp; ret — the leaf
    epilogue at 0x9ecdccc2) — nothing to activate.
    else -> replay the 3 instructions and continue at 0x9ecdcbbf.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE38  = 0x9E400C00
SITE    = 0x9ECDcBAD & 0xFFFFFFFF      # 0x9ecdcBAD
CONT_F  = 0xFFFFFFFF9ECDCBBF

SITE_OLD = bytes.fromhex(
    "488b4f08"              # mov rcx, [rdi+8]        (4B)
    "488bb100020000"        # mov rsi, [rcx+0x200]    (6B)
    "488d8ee8020000"        # lea rcx, [rsi+0x2e8]    (7B)
)                            # 17B total

CAVE38_ASM = f"""
    mov  rcx, qword ptr [rdi + 8]
    test rcx, rcx
    jnz  ok
    pop  rbp
    ret
ok:
    mov  rsi, qword ptr [rcx + 0x200]
    lea  rcx, [rsi + 0x2e8]
    jmp  {CONT_F:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE38_ASM, CAVE38)
if not enc:
    print("ASM FAILED"); sys.exit(1)
cave38 = bytes(enc)
print(f"cave38: {len(cave38):#x}B @ {CAVE38:#x}")
assert len(cave38) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = SITE - KTEXT
if bytes(img[off:off+len(SITE_OLD)]) != SITE_OLD:
    print(f"FAIL site {SITE:#x}: {bytes(img[off:off+len(SITE_OLD)]).hex()}")
    print(f"  expected: {SITE_OLD.hex()}")
    sys.exit(1)
off = CAVE38 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave38 {CAVE38:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

rel = CAVE38 - (SITE + 5)
off = SITE - KTEXT
img[off:off+len(SITE_OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(SITE_OLD) - 5)

off = CAVE38 - KTEXT
img[off:off+len(cave38)] = cave38

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave38 ---")
for i in md.disasm(cave38, CAVE38):
    print(f"  {i.address:#x}  {i.bytes.hex():<18} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP15#17: pmap-activate NULL-proc guard (cave38 @0x9E400C00)")
