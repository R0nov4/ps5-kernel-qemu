#!/usr/bin/env python3
"""WP12 fix #1 — cave v4: fn1 returns a true NULL for bogus objects.

User root-cause (verified against the image): when the flags-skip path leaves
rbx = a small non-canonical value (e.g. 2), the cave bogus branch jumps to
0x9e82d979 and flows to fn1's epilogue `mov rax, rbx` @0x9e82daa9 WITHOUT the
`xor ebx, ebx` that the release path performs at 0x9e82da8c.  fn1 therefore
returns the fake value (rax=2); the caller's `test rax, rax; je` @0x9e82fce2
sees non-NULL and links the "object": `mov [rax+8], rcx` @0x9e82fcf3 -> CR2=0xa.

Fix (user-specified): in the cave bogus branch, zero rbx BEFORE jumping to the
epilogue so `mov rax, rbx` returns a real NULL and the caller takes its own
NULL path (je 0x9e82fbe2).

Run AFTER wp11_patch_bogusobj.py (which writes the jump site at 0x9e82d93b and
the v1 cave); this script overwrites the cave body with v4.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
CAVE = 0x9EE30400

CAVE_ASM = """
mov r13, qword ptr [rbp - 0x40]
movabs rax, 0xffff000000000000
cmp rbx, rax
jb bogus
mov qword ptr [rbx], r14
movabs rax, 0xffffffff9e82d942
jmp rax
bogus:
xor ebx, ebx
movabs rax, 0xffffffff9e82d979
jmp rax
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, cnt = ks.asm(CAVE_ASM, CAVE)
cave_code = bytes(enc)
print(f"cave v4: {len(cave_code)} bytes @ {CAVE:#x} ({cnt} insns)")
assert len(cave_code) <= 64, "cave v4 overflows the reserved window"

img = bytearray(open(IMG, "rb").read())

# 1. verify the jump site 0x9e82d93b points at our cave (written by bogusobj)
off = 0x9E82D93B - KTEXT
cur = bytes(img[off:off + 5])
if cur[0] != 0xE9:
    print(f"FAIL: jump site 0x9e82d93b is {cur.hex()}, expected e9 rel32 (run wp11_patch_bogusobj.py first)")
    sys.exit(1)
rel = int.from_bytes(cur[1:5], "little", signed=True)
tgt = 0x9E82D93B + 5 + rel
if tgt != CAVE:
    print(f"FAIL: jump site targets {tgt:#x}, expected {CAVE:#x}")
    sys.exit(1)
print(f"jump site OK: 0x9e82d93b -> {tgt:#x}")

# 2. overwrite the cave body (v1/v3 -> v4)
cave_off = CAVE - KTEXT
print(f"cave old bytes: {bytes(img[cave_off:cave_off+16]).hex()}")
img[cave_off:cave_off + len(cave_code)] = cave_code

# 3. disassemble back for the log
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in md.disasm(cave_code, CAVE):
    print(f"  {i.address:#x}  {i.bytes.hex():<24} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK cave v4 written (bogus branch now zeroes rbx -> fn1 returns NULL)")
