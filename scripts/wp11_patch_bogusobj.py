#!/usr/bin/env python3
"""WP11 fix #6 — fn1 bogus-object guard (CR2=0x2 crash @0x9e82d93f).

On the flags-skip path rbx holds a small count (e.g. 2), and fn1 then treats
it as an object pointer: `mov [rbx], r14` -> write to VA 2.
Guard: if rbx < 0x1000 (bogus pointer), skip the whole object-write block
(0x9e82d93f..0x9e82d978) and land at the callback check 0x9e82d979.

Patch: [0x9e82d93b..0x9e82d942) (7 bytes: mov r13,[rbp-0x40]; mov [rbx],r14)
-> jmp cave @0x9EE30400 + 2 nops.
Cave: displaced mov; cmp rbx,0x1000; jb bogus; jmp back; bogus: jmp 0x9e82d979.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
CAVE = 0x9EE30400

ORIG = bytes.fromhex("4c8b6dc04c8933")

CAVE_ASM = f"""
mov r13, qword ptr [rbp - 0x40]
cmp rbx, 0x1000
jb bogus
mov rax, 0x9e82d93f
jmp rax
bogus:
mov rax, 0x9e82d979
jmp rax
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, cnt = ks.asm(CAVE_ASM, CAVE)
cave_code = bytes(enc)
print(f"cave: {len(cave_code)} bytes @ {CAVE:#x}")

img = bytearray(open(IMG, "rb").read())

# verify original
off = 0x9E82D93B - KTEXT
cur = bytes(img[off:off + 7])
if cur != ORIG:
    print(f"FAIL site: expected {ORIG.hex()}, found {cur.hex()}")
    sys.exit(1)

# verify cave area is dead ICC body (nonzero old code, not our previous caves)
cave_off = CAVE - KTEXT
print(f"cave area old bytes: {bytes(img[cave_off:cave_off+16]).hex()}")

# write cave
img[cave_off:cave_off + len(cave_code)] = cave_code

# write the jump
rel = CAVE - (0x9E82D93B + 5)
jmp = b"\xe9" + rel.to_bytes(4, "little", signed=True)
img[off:off + 7] = jmp + b"\x90\x90"

open(IMG, "wb").write(img)
print(f"OK bogus-object guard: 0x9e82d93b -> jmp {CAVE:#x} (rel {rel:+#x})")
