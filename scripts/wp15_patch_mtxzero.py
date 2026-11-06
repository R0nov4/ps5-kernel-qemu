#!/usr/bin/env python3
"""WP15 #10 — mtx acquire word==0 fast-path (spin timeout assert).

ROOT CAUSE (GDB-verified):
  (assertion) 0xffffffffa1978860 (tid 100000) has waited too long to
  acquire spin lock 0xffffffffa2229cc0 ((null)) (count: waiter 0 current 0)
  The acquire 0x9e8b7190 (called from the callout path
  0x9eb7439f <- 0x9ef8ae5e <- 0x9e655080 <- the vmwait/sleep chain) reads
  the mtx word and only fast-paths the DESIGNED free value 4:
    0x9e8b71ce  cmp rax, 4            ; free == 4
    0x9e8b71d2  jne 0x9e8b7238        ; word != 4 -> slow path
    0x9e8b71d4  mov eax, 4
    0x9e8b71d9  mov rcx, [rbp-0x30]   ; curthread
    0x9e8b71dd  lock cmpxchg [r14], rcx
  The lock at 0xa2229cc0 is a STACK-LOCAL mtx (beyond the image: offset
  0x3E39CA8 > image end) whose word = 0 — never mtx_init'd (its
  initializer was one of the NULL-guarded paths). Word 0 -> slow path ->
  the timeout check fires immediately (the TSC/timestamp residue makes
  'elapsed' huge) -> the assertion.

FIX (systemic — the whole never-initialized-zero-mtx family):
  cave32 @0x9E400900 replacing [0x9e8b71ce, 0x9e8b71e4):
    word == 4  -> the original CAS-from-4
    word == 0  -> CAS-from-0 (an uninitialized mtx is free; acquiring it
                  stores curthread and the unlock writes the designed 4 —
                  the lock SELF-HEALS to proper state after one cycle)
    otherwise  -> the original slow path 0x9e8b7238
  A designed lock never has word 0 (free = 4, held = curthread), so only
  our never-initialized locks take the new path.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE32  = 0x9E400900
SITE    = 0x9E8B71CE
SLOW_F  = 0xFFFFFFFF9E8B7238       # the slow path
ACQ_F   = 0xFFFFFFFF9E8B71E4       # 'acquired' continuation

SITE_OLD = bytes.fromhex("4883f8047564b804000000488b4dd0f0490fb10e7554")   # 23B

CAVE32_ASM = f"""
    cmp  rax, 4
    je   cas4
    test rax, rax
    jnz  slow
    xor  eax, eax
    mov  rcx, qword ptr [rbp - 0x30]
    lock cmpxchg qword ptr [r14], rcx
    jne  slow
    jmp  {ACQ_F:#x}
cas4:
    mov  eax, 4
    mov  rcx, qword ptr [rbp - 0x30]
    lock cmpxchg qword ptr [r14], rcx
    jne  slow
    jmp  {ACQ_F:#x}
slow:
    jmp  {SLOW_F:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE32_ASM, CAVE32)
if not enc:
    print("ASM FAILED"); sys.exit(1)
cave32 = bytes(enc)
print(f"cave32: {len(cave32):#x}B @ {CAVE32:#x}")
assert len(cave32) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = SITE - KTEXT
if bytes(img[off:off+len(SITE_OLD)]) != SITE_OLD:
    print(f"FAIL site {SITE:#x}: {bytes(img[off:off+len(SITE_OLD)]).hex()}")
    print(f"  expected: {SITE_OLD.hex()}")
    sys.exit(1)
off = CAVE32 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave32 {CAVE32:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

rel = CAVE32 - (SITE + 5)
off = SITE - KTEXT
img[off:off+len(SITE_OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(SITE_OLD) - 5)

off = CAVE32 - KTEXT
img[off:off+len(cave32)] = cave32

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave32 ---")
for i in md.disasm(cave32, CAVE32):
    print(f"  {i.address:#x}  {i.bytes.hex():<20} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP15#10: mtx acquire word==0 fast-path (cave32 @0x9E400900)")
