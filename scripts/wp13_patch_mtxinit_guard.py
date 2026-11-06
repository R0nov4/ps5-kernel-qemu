#!/usr/bin/env python3
"""WP13 fix #10 — mtx_init NULL/small-object entry guard (crash 0x9e8b7e35, CR2=0x18).

mtx_init fn 0x9e8b7dd0(mtx=rdi, name=rsi, ...):
    rbx = rdi                          ; the mtx object
    lea rdi, [rbx - 0x18]              ; lock-class object
    call leaf 0x9ee1e8d0               ; guarded by fix #9 (rdi=0 -> clean ret)
    mov qword ptr [rbx], 4             ; lock word := FREE — <<< CRASH with rbx=0x18
The mtx pointer is a NULL-parent computed value (parent+0x18 with parent=NULL,
the cold-boot malloc-NULL pattern). Hundreds of call sites -> entry guard:

  0x9e8b7dd0 (5B: push rbp; mov rbp,rsp; push rbx) -> jmp cave17
  cave17 @0x9EE31000:
      test rdi,rdi ; jz null_ret
      cmp rdi, 0x1000 ; jb null_ret    ; NULL + small offset (computed from a
                                       ;  NULL parent) — nothing to init
      push rbp; mov rbp,rsp; push rbx  ; replay displaced prologue
      jmp 0x9e8b7dd6                   ; continue at 'mov eax,ecx'
    null_ret: ret
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
CAVE17 = 0x9EE31000
ENTRY = 0x9e8b7dd0
ENTRY_OLD = bytes.fromhex("554889e553")     # push rbp; mov rbp,rsp; push rbx
PROLOGUE = bytes.fromhex("554889e553")      # replayed fully in the cave
assert len(ENTRY_OLD) == 5

CAVE17_ASM = """
test rdi, rdi
jz null_ret
movabs rax, 0x1000
cmp rdi, rax
jb null_ret
push rbp
mov rbp, rsp
push rbx
jmp 0x9e8b7dd6
null_ret:
ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE17_ASM, CAVE17)
cave17 = bytes(enc)
print(f"cave17: {len(cave17)}B @ {CAVE17:#x}")

img = bytearray(open(IMG, "rb").read())
off = ENTRY - KTEXT
if bytes(img[off:off+5]) != ENTRY_OLD:
    print(f"FAIL entry: {bytes(img[off:off+5]).hex()}"); sys.exit(1)

rel = CAVE17 - (ENTRY + 5)
img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)
off_c = CAVE17 - KTEXT
img[off_c:off_c+len(cave17)] = cave17

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- entry ---")
for i in md.disasm(bytes(img[off:off+10]), ENTRY):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
print("--- cave17 ---")
for i in md.disasm(cave17, CAVE17):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP13 fix #10: mtx_init NULL/small object -> clean skip")
