#!/usr/bin/env python3
"""WP13 fix #9 — lock-setup leaf NULL-object guard (crash 0x9ee1e9d0, CR2=0x0 WRITE).

Leaf fn 0x9ee1e8d0 (called from 16 sites in the mtx_init family
0x9e8b7db0..0x9f03b309): matches rsi against the 15 static region-class
globals 0xA09583C0..0xA0958430, then writes the lock descriptor:
    0x9ee1e8d0  test rdx,rdx ; je 0x9ee1e9df (error fn)
    ...15 cmp [global],rsi -> size codes 0..0xE * 0x1000000...
    0x9ee1e964  mov eax,[rdi+8]           (no-match path — also NULL-deref)
    0x9ee1e9cd  or r8d, eax
    0x9ee1e9d0  mov qword ptr [rdi], rdx  ; <<< CRASH — rdi = NULL lock object
    0x9ee1e9d3  or r8d, 0x10000
    0x9ee1e9da  mov dword ptr [rdi+8], r8d
    0x9ee1e9de  ret

The mtx object is NULL when its containing structure failed to allocate
(the recurring cold-boot malloc-NULL pattern). Guard at the leaf entry:

  0x9ee1e8d0 (9B: test rdx,rdi + je) -> jmp cave16 + 4 nops
  cave16 @0x9EE30F00:
      test rdi,rdi ; jz clean_ret          ; NULL lock -> nothing to init
      test rdx,rdx ; jz 0x9ee1e9df         ; original error path preserved
      jmp 0x9ee1e8d9                       ; continue the compare cascade
    clean_ret: ret
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
CAVE16 = 0x9EE30F00
SPAN = 0x9ee1e8d0
SPAN_OLD = bytes.fromhex("4885d2" "0f8406010000")   # test rdx,rdi; je 0x9ee1e9df
assert len(SPAN_OLD) == 9

CAVE16_ASM = """
test rdi, rdi
jz clean_ret
test rdx, rdx
jz 0x9ee1e9df
jmp 0x9ee1e8d9
clean_ret:
ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE16_ASM, CAVE16)
cave16 = bytes(enc)
print(f"cave16: {len(cave16)}B @ {CAVE16:#x}")

img = bytearray(open(IMG, "rb").read())
off = SPAN - KTEXT
if bytes(img[off:off+9]) != SPAN_OLD:
    print(f"FAIL span: {bytes(img[off:off+9]).hex()}"); sys.exit(1)

rel = CAVE16 - (SPAN + 5)
img[off:off+9] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * 4
off_c = CAVE16 - KTEXT
img[off_c:off_c+len(cave16)] = cave16

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- span ---")
for i in md.disasm(bytes(img[off:off+9]), SPAN):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
print("--- cave16 ---")
for i in md.disasm(cave16, CAVE16):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP13 fix #9: NULL lock object -> leaf returns without writing")
