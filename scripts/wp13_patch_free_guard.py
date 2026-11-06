#!/usr/bin/env python3
"""WP13 fix #1 — free()/contigfree NULL-descriptor guard (crash 0x9eff8e19, CR2=0x6b).

User root-cause (verified by full disasm): fn 0x9eff8df0 is a VOID free-family
function ('contigfree'-style: rdi=addr, rsi=ctx). Designed NULL exit already
exists: 0x9eff8e01 'je 0x9eff8e63' -> pure pop-epilogue + ret (no rax set).

Crash chain:
  0x9eff8e09  call 0x9ecce330      ; pmap_kextract(addr)
  0x9eff8e11  call 0x9ea05a70      ; zone/slab descriptor lookup(phys) -> NULL
  0x9eff8e19  movzx r12d,[rax+0x6b] ; <<< CRASH (rax=0, CR2=0x6b)
  ... second lookup 0x9ef79290 (segment) would crash the same way at
  0x9eff8e35  mov rdi,[rax+8]      ; if it returns NULL.

Fix (user-specified cave option, guards BOTH lookups; real frees unaffected):
  site1 0x9eff8e16 (8B: mov r14,r15 ; movzx r12d,[rax+0x6b]) -> jmp cave8.partA
      partA: rax==NULL -> clean exit 0x9eff8e63; else replay + jmp 0x9eff8e1e
  site2 0x9eff8e35 (7B: mov rdi,[rax+8] ; test rdi,rdi) -> jmp cave8.partB
      partB: rax==NULL -> clean exit 0x9eff8e63; else replay; rdi==NULL ->
             original panic branch 0x9eff8efa; else jmp 0x9eff8e42
  clean_exit @cave8+0x80: movabs rdx,0xffffffff9eff8e63 ; jmp rdx
cave8 @0x9EE30A00 (dead ICC body; verified clear of the trampoline patch
table — phys 0x1ee30a range has no patches.inc entry).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
CAVE8  = 0x9EE30A00   # partA
CAVE8B = 0x9EE30A40   # partB
CAVE8X = 0x9EE30A80   # clean exit

SITE1 = 0x9eff8e16
SITE1_OLD = bytes.fromhex("4d89fe440fb6606b")      # mov r14,r15; movzx r12d,[rax+0x6b]
assert len(SITE1_OLD) == 8

SITE2 = 0x9eff8e35
SITE2_OLD = bytes.fromhex("488b780848 85ff".replace(" ", ""))  # mov rdi,[rax+8]; test rdi,rdi
assert len(SITE2_OLD) == 7

PARTA_ASM = """
test rax, rax
jz 0x9EE30A80
mov r14, r15
movzx r12d, byte ptr [rax + 0x6b]
movabs rdx, 0xffffffff9eff8e1e
jmp rdx
"""

PARTB_ASM = """
test rax, rax
jz 0x9EE30A80
mov rdi, qword ptr [rax + 8]
test rdi, rdi
jnz ok
movabs rdx, 0xffffffff9eff8efa
jmp rdx
ok:
movabs rdx, 0xffffffff9eff8e42
jmp rdx
"""

CLEANX_ASM = """
movabs rdx, 0xffffffff9eff8e63
jmp rdx
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    return bytes(enc)

parta = asm(PARTA_ASM, CAVE8)
partb = asm(PARTB_ASM, CAVE8B)
cleanx = asm(CLEANX_ASM, CAVE8X)
print(f"partA: {len(parta)}B @ {CAVE8:#x}  partB: {len(partb)}B @ {CAVE8B:#x}  clean: {len(cleanx)}B @ {CAVE8X:#x}")
assert len(parta) <= 0x40 and len(partb) <= 0x40 and len(cleanx) <= 0x40

img = bytearray(open(IMG, "rb").read())

# --- verify original bytes ---
off1, off2 = SITE1 - KTEXT, SITE2 - KTEXT
if bytes(img[off1:off1+8]) != SITE1_OLD:
    print(f"FAIL site1: {bytes(img[off1:off1+8]).hex()} != {SITE1_OLD.hex()}"); sys.exit(1)
if bytes(img[off2:off2+7]) != SITE2_OLD:
    print(f"FAIL site2: {bytes(img[off2:off2+7]).hex()} != {SITE2_OLD.hex()}"); sys.exit(1)
print(f"cave8 area old bytes (dead ICC body): {bytes(img[CAVE8-KTEXT:CAVE8-KTEXT+16]).hex()}")

# --- site patches: jmp rel32 + nop pad ---
for site, ln, tgt in ((SITE1, 8, CAVE8), (SITE2, 7, CAVE8B)):
    rel = tgt - (site + 5)
    off = site - KTEXT
    img[off:off+ln] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (ln - 5)

# --- caves ---
for code, base in ((parta, CAVE8), (partb, CAVE8B), (cleanx, CAVE8X)):
    off = base - KTEXT
    img[off:off+len(code)] = code

# --- log ---
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- site1 0x9eff8e16 ---")
for i in md.disasm(bytes(img[off1:off1+8]), SITE1):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
print("--- site2 0x9eff8e35 ---")
for i in md.disasm(bytes(img[off2:off2+7]), SITE2):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
for name, code, base in (("partA", parta, CAVE8), ("partB", partb, CAVE8B), ("clean_exit", cleanx, CAVE8X)):
    print(f"--- {name} ---")
    for i in md.disasm(code, base):
        print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP13 fix #1: free() NULL-descriptor/NULL-segment -> clean void exit")
