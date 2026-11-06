#!/usr/bin/env python3
"""WP12 fix #8 — free-lock no-op guard in the mtx-unlock retry loop (v2: canary r14 restore).

The 'intr sources' stage creates a fresh event object (zero page) whose
embedded lock word [+0x18] is 0 (never locked).  The unlock path
0x9f03bb20 walks its contended-retry loop and dereferences the owner
unconditionally:
    0x9f03bccd  mov r13, [rbx+0x18]     ; lock word (owner|flags)
    0x9f03bcf1  test r13b, 1
    0x9f03bcfb  and r13, ~0xF           ; owner (0 for a free lock!)
    0x9f03bcff  mov eax, [r13+0x400]    ; owner->field -> CR2=0x400
Unlocking a lock nobody holds is a no-op on any sane implementation — the
live machine never hit it because the registry objects came pre-locked
from its own boot.

Fix: cave5 guard — NULL owner -> jump to the function's clean exit
0x9f03c067 (just a curthread stat bump + epilogue).  In-place:
0x9f03bcff..0x9f03bd0e (16 bytes) -> jmp cave5 + 11 nops.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
CAVE5 = 0x9EE30700

SPAN_OLD = bytes.fromhex(
    "418b8500040000"   # mov eax,[r13+0x400]
    "83f804"           # cmp eax,4
    "0f8531010000"     # jne 0x9f03be40
)
assert len(SPAN_OLD) == 16

CAVE5_ASM = """
test r13, r13
jz free_exit
mov eax, dword ptr [r13 + 0x400]
cmp eax, 4
jne 0x9f03be40
jmp 0x9f03bd0f
free_exit:
movabs r14, 0xffffffffa1d0c310
jmp 0x9f03c067
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE5_ASM, CAVE5)
cave5 = bytes(enc)
print(f"cave5: {len(cave5)} bytes @ {CAVE5:#x}")

img = bytearray(open(IMG, "rb").read())
off = 0x9f03bcff - KTEXT
cur = bytes(img[off:off + 16])
if cur != SPAN_OLD:
    print(f"FAIL span: {cur.hex()} != {SPAN_OLD.hex()}")
    sys.exit(1)

rel = CAVE5 - (0x9f03bcff + 5)
img[off:off + 16] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * 11

off_c5 = CAVE5 - KTEXT
print(f"cave5 area old bytes: {bytes(img[off_c5:off_c5+16]).hex()}")
img[off_c5:off_c5 + len(cave5)] = cave5

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- site ---")
for i in md.disasm(bytes(img[off:off + 16]), 0x9f03bcff):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
print("--- cave5 ---")
for i in md.disasm(cave5, CAVE5):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK free-lock no-op guard: NULL owner -> clean exit 0x9f03c067")
