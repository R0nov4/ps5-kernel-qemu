#!/usr/bin/env python3
"""WP12 fix #2 (defense-in-depth, optional per user) — caller-side
canonical-VA guard at the fn3 call site.

Even with cave v4 making fn1 return a true NULL, any *other* path that leaks
a non-canonical "object pointer" into rax would still crash the caller at
`mov [rax+8], rcx` @0x9e82fcf3.  Belt-and-suspenders: replace

    0x9e82fce2  test rax, rax          (3)
    0x9e82fce5  je 0x9e82fbe2          (6)

with a jump to cave2 @0x9EE30480 which reproduces the original NULL check and
additionally rejects rax < 0xffff000000000000 (non-canonical) by taking the
kernel's own NULL path 0x9e82fbe2 with rax zeroed and identical flags.

State contract:
  - rax == 0            -> 0x9e82fbe2, flags ZF=1 exactly like the original je
  - rax canonical       -> 0x9e82fceb (fall-through), flags unused downstream
  - rax bogus (< thresh)-> 0x9e82fbe2 with rax=0 (new guarded behaviour)
rdx is clobbered (caller-saved; next written at 0x9e82fcfc before any use).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
CAVE2 = 0x9EE30480
SITE = 0x9E82FCE2

ORIG = bytes.fromhex("4885c00f84f7feffff")   # test rax,rax ; je 0x9e82fbe2

CAVE2_ASM = """
test rax, rax
je safe
movabs rdx, 0xffff000000000000
cmp rax, rdx
jb safe
movabs rdx, 0xffffffff9e82fceb
jmp rdx
safe:
xor eax, eax
test rax, rax
movabs rdx, 0xffffffff9e82fbe2
jmp rdx
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, cnt = ks.asm(CAVE2_ASM, CAVE2)
cave2 = bytes(enc)
print(f"cave2: {len(cave2)} bytes @ {CAVE2:#x} ({cnt} insns)")
assert len(cave2) <= 64

img = bytearray(open(IMG, "rb").read())

# 1. verify the site is still the original test+je
off = SITE - KTEXT
cur = bytes(img[off:off + 9])
if cur != ORIG:
    print(f"FAIL site: expected {ORIG.hex()}, found {cur.hex()}")
    sys.exit(1)

# 2. write cave2 into the dead ICC body
cave_off = CAVE2 - KTEXT
print(f"cave2 area old bytes: {bytes(img[cave_off:cave_off+16]).hex()}")
img[cave_off:cave_off + len(cave2)] = cave2

# 3. patch the site: jmp rel32 + 4 nops (9 bytes total)
rel = CAVE2 - (SITE + 5)
jmp = b"\xe9" + rel.to_bytes(4, "little", signed=True)
img[off:off + 9] = jmp + b"\x90" * 4

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave2 ---")
for i in md.disasm(cave2, CAVE2):
    print(f"  {i.address:#x}  {i.bytes.hex():<24} {i.mnemonic} {i.op_str}")
print("--- site ---")
for i in md.disasm(bytes(img[off:off + 9]), SITE):
    print(f"  {i.address:#x}  {i.bytes.hex():<24} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print(f"OK caller guard: 0x9e82fce2 -> jmp {CAVE2:#x} (rel {rel:+#x})")
