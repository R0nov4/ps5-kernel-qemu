#!/usr/bin/env python3
"""WP12 fix #3 — walker NULL-object guard (stage-49 'fakepg' zone create, CR2=0x18).

Crash: walker 0x9e82f820 on the 'UMA Zones' master template (0xa18eaf40):
  root = [zone+0x68] = 0xa18eafb0 (registry list head, valid)
  r14  = [root+0x10] = 0          (EMPTY registry — live dump never populated it;
                                   on live HW stage 48's conversion fills it, we
                                   stubbed that redundant re-run)
  lea rdi,[r14+0x18] = 0x18 -> mtx_lock(0x18) -> CR2=0x18 @0x9e8b6a2d

Fix: give the walker the NULL-object exit its design already supports
(fn4 NULL-checks the walker result: `test rax,rax; je 0x9e82f97c`).

In-place rewrite of 0x9e82f840..0x9e82f85f (32 bytes):
    mov r14,[rax+0x10]          (kept)
    test r14, r14               (new)
    jz cave3                    (new)
    lea rdi,[r14+0x18]          (kept)
    xor esi/edx/ecx             (kept)
    call 0x9e8b6a00             (kept, rel adjusted)
    nop x4                      (pad)
Plus redirect the root==NULL je: 0x9e82f83e '74 06' -> '74 04'
(the old xor r14d,r14d at 0x9e82f846 is subsumed: reaching 0x9e82f837
already implies rsi==0 => r14==0).

cave3 @0x9EE30500 (dead ICC body):
    xor eax, eax                ; return NULL
    movabs rdx, 0xffffffff9e82f892
    jmp rdx                     ; walker epilogue (add rsp,8; pop rbx/r14/r15/rbp; ret)
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
CAVE3 = 0x9EE30500

JE_OLD = bytes.fromhex("7406")                    # je 0x9e82f846
JE_NEW = bytes.fromhex("7404")                    # je 0x9e82f844 (the new test)
SPAN_OLD = bytes.fromhex(
    "4c8b7010"        # mov r14,[rax+0x10]
    "eb03"            # jmp 0x9e82f849
    "4531f6"          # xor r14d,r14d
    "498d7e18"        # lea rdi,[r14+0x18]
    "31f6" "31d2" "31c9"
    "e8a8710800"      # call 0x9e8b6a00
    "0f1f840000000000"  # nop8
)
assert len(SPAN_OLD) == 32

SPAN_NEW_ASM = """
mov r14, qword ptr [rax + 0x10]
test r14, r14
jz 0x9EE30500
lea rdi, qword ptr [r14 + 0x18]
xor esi, esi
xor edx, edx
xor ecx, ecx
call 0x9e8b6a00
nop
nop
nop
nop
"""

CAVE3_ASM = """
xor eax, eax
movabs rdx, 0xffffffff9e82f892
jmp rdx
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(SPAN_NEW_ASM, 0x9e82f840)
span_new = bytes(enc)
print(f"walker span: {len(span_new)} bytes (budget 32)")
assert len(span_new) == 32, f"span length {len(span_new)} != 32"

enc3, _ = ks.asm(CAVE3_ASM, CAVE3)
cave3 = bytes(enc3)
print(f"cave3: {len(cave3)} bytes @ {CAVE3:#x}")

img = bytearray(open(IMG, "rb").read())

# verify original bytes
off_je = 0x9e82f83e - KTEXT
off_span = 0x9e82f840 - KTEXT
if bytes(img[off_je:off_je + 2]) != JE_OLD:
    print(f"FAIL je site: {bytes(img[off_je:off_je+2]).hex()} != {JE_OLD.hex()}")
    sys.exit(1)
if bytes(img[off_span:off_span + 32]) != SPAN_OLD:
    print(f"FAIL span: {bytes(img[off_span:off_span+32]).hex()}")
    sys.exit(1)

# 1. redirect the root==NULL je
img[off_je:off_je + 2] = JE_NEW

# 2. rewrite the span
img[off_span:off_span + 32] = span_new

# 3. write cave3
off_c3 = CAVE3 - KTEXT
print(f"cave3 area old bytes: {bytes(img[off_c3:off_c3+16]).hex()}")
img[off_c3:off_c3 + len(cave3)] = cave3

# log the result
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- walker 0x9e82f837.. ---")
for i in md.disasm(bytes(img[0x9e82f837-KTEXT:0x9e82f868-KTEXT]), 0x9e82f837):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
print("--- cave3 ---")
for i in md.disasm(cave3, CAVE3):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK walker NULL-object guard: empty registry -> walker returns NULL (fn4 handles it)")
