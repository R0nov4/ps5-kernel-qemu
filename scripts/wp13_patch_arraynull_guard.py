#!/usr/bin/env python3
"""WP13 fix #6 — array-slot NULL guard (crash 0x9e86e124, CR2=0x0 WRITE).

Sysinit stage (mutex-pool/registry family) fn 0x9e86dff0:
    malloc(0x1008, ctx 0x9FEB55F0, 0x102) @0x9e86e00f -> NULL (clean, fix #5)
    mov [0xA191B560], rax            ; array := NULL
    ... walks the name list (global 0xA191B568 — valid string), then:
    mov rax, [0xA191B560]            ; rax = NULL
    movsxd rcx, r14d                 ; slot index
    mov qword [rax + rcx*8], 0       ; <<< CRASH — write slot into NULL array
    call 0x9e8b7dd0(0xA191B558, ...) ; registration
    mov dword [0xA191B588-ish], 1    ; initialized flag; epilogue

Fix: skip only the slot write when the array is NULL (minimal crash-loop
guard; the registration/flag continue normally).
    0x9e86e124 (8B) -> jmp cave12 + 3 nops
    cave12 @0x9EE30C00:
        test rax,rax ; jz done ; mov [rax+rcx*8], 0 ; done: jmp 0x9e86e12c
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
CAVE12 = 0x9EE30C00
SPAN = 0x9e86e124
SPAN_OLD = bytes.fromhex("48c704c800000000")
assert len(SPAN_OLD) == 8

CAVE12_ASM = """
test rax, rax
jz done
mov qword ptr [rax + rcx*8], 0
done:
jmp 0x9e86e12c
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE12_ASM, CAVE12)
cave12 = bytes(enc)
print(f"cave12: {len(cave12)}B @ {CAVE12:#x}")

img = bytearray(open(IMG, "rb").read())
off = SPAN - KTEXT
if bytes(img[off:off+8]) != SPAN_OLD:
    print(f"FAIL span: {bytes(img[off:off+8]).hex()}"); sys.exit(1)

rel = CAVE12 - (SPAN + 5)
img[off:off+8] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * 3
off_c = CAVE12 - KTEXT
img[off_c:off_c+len(cave12)] = cave12

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- span ---")
for i in md.disasm(bytes(img[off:off+8]), SPAN):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
print("--- cave12 ---")
for i in md.disasm(cave12, CAVE12):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP13 fix #6: NULL array -> slot write skipped")
