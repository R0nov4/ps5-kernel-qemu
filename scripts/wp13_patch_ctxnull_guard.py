#!/usr/bin/env python3
"""WP13 fix #3 — zone-configure NULL-ctx guard (crash 0x9e82961a, CR2=0x40).

Call chain (post-randompid, SceSwapper): callers @0x9eff9b54 / 0x9eff9ba0
allocate an object via the heap allocator 0x9e82b0e0 (returns NULL on cold
boot — zone tables empty, same class as WP12 fix #10), store the result into
[r15+0x20]/[r15+0x28], check only [r15+0x18] (count) — NOT the allocation —
and pass rdi=rax=NULL to the configure accessor 0x9e829610:
    0x9e829617  mov r14, rdi
    0x9e82961a  mov rdi, [rdi+0x40]     ; <<< CRASH (NULL ctx, CR2=0x40)
    ... lock [ctx+0x40]+0x18, write [ctx+0x170]=rsi, unlock

The function is void; a NULL ctx means "object was never created" — cold-boot
semantics: skip configuration entirely.

Fix (WP12 fix #10 pattern): entry guard @0x9e829610 -> cave9 @0x9EE30AC0:
    test rdi,rdi ; jz nullret          ; NULL ctx -> bare ret (void)
    replay displaced 10-byte prologue (push rbp; mov rbp,rsp; push r14;
    push rbx; mov r14,rdi) ; jmp 0x9e82961a
    nullret: ret
cave9 is in the dead ICC body (phys 0x1ee30a range — clear in patches.inc).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
CAVE9 = 0x9EE30AC0
ENTRY = 0x9e829610

ENTRY_OLD = bytes.fromhex("554889e541")            # push rbp; mov rbp,rsp; [41]56
PROLOGUE  = bytes.fromhex("554889e5415653 4989fe".replace(" ", ""))
assert len(PROLOGUE) == 10

CAVE9_ASM = """
test rdi, rdi
jz nullret
push rbp
mov rbp, rsp
push r14
push rbx
mov r14, rdi
jmp 0x9e82961a
nullret:
ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE9_ASM, CAVE9)
cave9 = bytes(enc)
print(f"cave9: {len(cave9)}B @ {CAVE9:#x}")

img = bytearray(open(IMG, "rb").read())

off_e = ENTRY - KTEXT
if bytes(img[off_e:off_e+5]) != ENTRY_OLD:
    print(f"FAIL entry: {bytes(img[off_e:off_e+5]).hex()} != {ENTRY_OLD.hex()}")
    sys.exit(1)
if bytes(img[off_e:off_e+10]) != PROLOGUE:
    print(f"FAIL prologue: {bytes(img[off_e:off_e+10]).hex()} != {PROLOGUE.hex()}")
    sys.exit(1)
print(f"cave9 area old bytes: {bytes(img[CAVE9-KTEXT:CAVE9-KTEXT+16]).hex()}")

rel = CAVE9 - (ENTRY + 5)
img[off_e:off_e+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)
off_c9 = CAVE9 - KTEXT
img[off_c9:off_c9+len(cave9)] = cave9

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- entry ---")
for i in md.disasm(bytes(img[off_e:off_e+10]), ENTRY):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
print("--- cave9 ---")
for i in md.disasm(cave9, CAVE9):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP13 fix #3: NULL ctx -> clean void skip")
