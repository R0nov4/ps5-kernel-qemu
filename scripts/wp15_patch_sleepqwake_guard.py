#!/usr/bin/env python3
"""WP15 #8 — sleepq wakeup NULL-sq guard (crash 0x9f00ae7c, CR2=0x20).

ROOT CAUSE (GDB-verified):
  The boot thread slept via vmwait/msleep (wchan string 'vmwait' @0x9f664852
  on the stack, timeout 1000 ticks): WP14's cave23 made sleepq_add a no-op
  for td_sleepqueue==NULL — so the thread context-switched away WITHOUT
  being linked into any sleepqueue. When the sleep ends (timeout/wakeup),
  the removal path runs:
    0x9f00b2d0(td, wchan):  hash wchan -> sleepq_chains[0xa21dc300] bucket
      -> walk the chain comparing sq->wchan (@+0x40) -> r12 = found sq (0!)
    0x9f00b334  rax = td->td_wchan ([td+0xf8]); wchan matches ->
    0x9f00b361  mov rdi, r12 ; mov rsi, r14 ; xor edx,edx
    0x9f00b369  call 0x9f00ae50             ; sleepq_remove_thread
    0x9f00ae7c  dec dword [rdi + rax*4 + 0x20]   <<< CRASH (sq==NULL)
  (caller chain: 0x9eff6337 (the thread-wakeup path) -> 0x9f00b2d0 ->
   0x9f00ae50(NULL, td).)

FIX: cave31 @0x9E400880 — guard the call site:
    r12 (the found sleepqueue) == 0 -> the thread is not on any queue ->
    skip the remove-thread call entirely (eax = 0 = 'no thread removed')
    and continue at 0x9f00b36e (the designed post-call flow).
    non-zero -> replay 'mov rdi,r12; mov rsi,r14; xor edx,edx', CALL
    0x9f00ae50 (the original call — the return address stays correct),
    then jmp 0x9f00b36e.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE31  = 0x9E400880
SITE    = 0x9F00B361
SITE_END = 0x9F00B36F
CONT_F  = 0xFFFFFFFF9F00B36E      # mov rdi, [r14]  (post-call continuation)
REMOV_F = 0xFFFFFFFF9F00AE50     # sleepq_remove_thread(sq, td, 0)

SITE_OLD = bytes.fromhex("4c89e74c89f631d2e8e2faffff")   # 14B

CAVE31_ASM = f"""
    test r12, r12
    jnz  go
    xor  eax, eax
    jmp  {CONT_F:#x}
go:
    mov  rdi, r12
    mov  rsi, r14
    xor  edx, edx
    call {REMOV_F:#x}
    jmp  {CONT_F:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE31_ASM, CAVE31)
if not enc:
    print("ASM FAILED"); sys.exit(1)
cave31 = bytes(enc)
print(f"cave31: {len(cave31):#x}B @ {CAVE31:#x}")
assert len(cave31) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = SITE - KTEXT
if bytes(img[off:off+len(SITE_OLD)]) != SITE_OLD:
    print(f"FAIL site {SITE:#x}: {bytes(img[off:off+len(SITE_OLD)]).hex()} != {SITE_OLD.hex()}")
    sys.exit(1)
off = CAVE31 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave31 {CAVE31:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

rel = CAVE31 - (SITE + 5)
off = SITE - KTEXT
img[off:off+len(SITE_OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(SITE_OLD) - 5)

off = CAVE31 - KTEXT
img[off:off+len(cave31)] = cave31

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave31 ---")
for i in md.disasm(cave31, CAVE31):
    print(f"  {i.address:#x}  {i.bytes.hex():<16} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP15#8: sleepq wakeup NULL-sq guard (cave31 @0x9E400880)")
