#!/usr/bin/env python3
"""WP15 #7 — bucket-list remove never-linked guard (crash 0x9ea05bfe, CR2=0x0).

ROOT CAUSE: with the bucket array seeded to zero RAM (WP15#6), the lookup
function 0x9ea055b0 "finds" the all-zero vm_page at the array slot (the
order@+0x68 and domain@+0x6b checks match trivially on zeros) and calls the
bucket-list REMOVE 0x9ea05bd0 on it:
    0x9ea05bd6  mov rax, [rsi]        ; elm->next  = 0
    0x9ea05bd9  test rax, rax
    0x9ea05bdc  je 0x9ea05bfa         ; tail path
    0x9ea05bfa  mov rcx, [rsi+8]      ; elm->prev  = 0
    0x9ea05bfe  cmp [rcx], rsi        ; <<< CRASH (rcx==0)
  The fake zero page was never linked into the bucket's object list
  (links {next@+0x00, prev@+0x08} both zero).

FIX: cave30 @0x9E400800 — entry guard:
    [rsi+8] (elm->prev) == 0 -> never linked -> jump straight to the
    designed tail of the function (0x9ea05c21 'mov byte [rsi+0x68], 0xb'
    = the "bucket = none" marker), skipping the assert checks, the
    unlink writes AND the count decrement (a never-counted page must not
    decrement). Otherwise replay the 3 replaced instructions and continue
    on the original paths.
  Protects all 5 callers (0x9ea05693, 0x9ea05919, 0x9ea059a1,
  0x9ea05f91, 0x9ea063ab).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE30  = 0x9E400800
SITE    = 0x9EA05BD6
MARKER_F = 0xFFFFFFFF9EA05C21     # mov byte [rsi+0x68], 0xb  (designed tail)
TAIL_F   = 0xFFFFFFFF9EA05BFA     # original tail path
MID_F    = 0xFFFFFFFF9EA05BDE     # original mid path (assert + unlink)

SITE_OLD = bytes.fromhex("488b064885c0741c")   # mov rax,[rsi]; test rax,rax; je +0x1c (8B)

CAVE30_ASM = f"""
    cmp  qword ptr [rsi + 8], 0
    jne  linked
    jmp  {MARKER_F:#x}
linked:
    mov  rax, qword ptr [rsi]
    test rax, rax
    je   {TAIL_F:#x}
    jmp  {MID_F:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE30_ASM, CAVE30)
if not enc:
    print("ASM FAILED"); sys.exit(1)
cave30 = bytes(enc)
print(f"cave30: {len(cave30):#x}B @ {CAVE30:#x}")
assert len(cave30) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = SITE - KTEXT
if bytes(img[off:off+len(SITE_OLD)]) != SITE_OLD:
    print(f"FAIL site {SITE:#x}: {bytes(img[off:off+len(SITE_OLD)]).hex()} != {SITE_OLD.hex()}")
    sys.exit(1)
off = CAVE30 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave30 {CAVE30:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

rel = CAVE30 - (SITE + 5)
off = SITE - KTEXT
img[off:off+len(SITE_OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(SITE_OLD) - 5)

off = CAVE30 - KTEXT
img[off:off+len(cave30)] = cave30

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave30 ---")
for i in md.disasm(cave30, CAVE30):
    print(f"  {i.address:#x}  {i.bytes.hex():<16} {i.mnemonic} {i.op_str}")
o = SITE - KTEXT
for i in md.disasm(bytes(img[o:o+8]), 0xFFFFFFFF9EA05BD6):
    print(f"  hook {i.address:#x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP15#7: bucket-list remove never-linked guard (cave30 @0x9E400800)")
