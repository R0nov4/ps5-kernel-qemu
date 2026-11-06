#!/usr/bin/env python3
"""WP17 #19 — the witness owner-list plausibility guard (cave79 @0x9E402180)
          (crash 0xffffffff9e81d975 GPF — the non-canonical owner list).

ROOT CAUSE:
  The witness bookkeeping's owner-list link (the deep path after the
  append): rax = [r13 + 0x128] (the previous owner's witness list tail)
  — with the never-initialized lock graph this reads GARBAGE (a
  non-canonical value) -> 'mov [rax + 0x68], rcx' -> #GP.

FIX — hook [0x9e81d975, 0x9e81d97a) (5B: 'mov [rax+0x68],rcx' + the
  REX head of 'mov [r13],r12'): an implausible owner list (NULL or
  bits 63..48 != 0xffff) -> skip the two owner-list stores (the third
  store 'mov [r12+0x68], r13' still runs — a harmless value write into
  the witness page); plausible -> replay both stores -> 0x9e81d97d.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE79 = 0x9E402180
S79, S79E = 0x9E81D975, 0x9E81D97A          # mov [rax+0x68],rcx; [4d]89.. (5B)
CONT79 = 0xFFFFFFFF9E81D97D                  # 'mov [r12+0x68], r13'

OLD79 = bytes.fromhex("488948684d")          # mov [rax+0x68],rcx; 4d

C79 = f"""
    test rax, rax
    jz   skip
    mov  rdx, rax
    shr  rdx, 48
    cmp  edx, 0xffff
    jne  skip
    mov  qword ptr [rax + 0x68], rcx
    mov  qword ptr [r13], r12
    jmp  {CONT79:#x}
skip:
    jmp  {CONT79:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C79, CAVE79)
print(f"cave79: {len(code):#x}B @ {CAVE79:#x}  hook {S79:#x} (5B)")
assert len(code) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = S79 - KTEXT
site = bytes(img[off:off+len(OLD79)])
if site[:1] == b"\xe9":
    rel_expect = CAVE79 - (S79 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S79:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S79:#x}: already hooked to cave79 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD79:
        print(f"FAIL site {S79:#x}: {site.hex()} != {OLD79.hex()}"); sys.exit(1)
    hooked = False

off = CAVE79 - KTEXT
cur = bytes(img[off:off+len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    img[off:off+0x80] = b"\xcc" * 0x80
    print(f"cave {CAVE79:#x}: stale body — blanking for rewrite")
print("site + cave assertions OK")

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE79 - (S79 + 5)
    off = S79 - KTEXT
    img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave79 (witness owner-list guard) ---")
for i in md.disasm(code, CAVE79):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP17#19: witness owner-list plausibility guard (cave79)")
