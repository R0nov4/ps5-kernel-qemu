#!/usr/bin/env python3
"""WP16 #14 — zone chunk-import page bump (crash 0x9e82b298 CR2=0xb0 R).

ROOT CAUSE (GDB):
  The malloc large path (0x9e82e080 wrapper -> 0x9e82b260 the zone-chunk
  allocator) calls the zone's IMPORT function: 'mov r12, [rdi+0xb0]' —
  the zone object's import slot = NULL (the zone was never initialized —
  the WP13 family) -> 'call r12' would jump to NULL; the earlier probe
  check already dereferenced [rdi+0xb0] at 0x9e82b298 -> CR2=0xb0.
  The import = 'give me 1 page for the zone chunk' (rdx=1 at the call);
  the object lands in [rbp-0x40] and rax (the function's return).

FIX — cave56 @0x9E401500 replacing [0x9e82b298, 0x9e82b29f) (7B:
  'mov r12,[rdi+0xb0]'):
    - a REAL import (r12 != 0): replay, continue 0x9e82b29f (the
      designed probe-check + import call)
    - NULL import: bump one 16KB page from the shared malloc window
      ([0x3F1A1000, 0x3F200000), state @0x3F1A0830 — the same pool as
      cave50/cave51), [rbp-0x40] := page, rax := page, then jump to the
      designed return tail 0x9e82b414 (the r13 balance check + the
      epilogue — rax preserved) — the caller (0x9e82e080: 'test rax,rax;
      je fail' + the 0x9e8f3d80 fill loop with OUR cave46 early-exit)
      proceeds with real memory.
    - window exhaustion: the designed fail path 0x9e82b409.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE56 = 0x9E401500
S56, S56E = 0x9E82B298, 0x9E82B29F          # mov r12,[rdi+0xb0] (7B)
BUMP_SLOT = 0xFFFF8E773F1A0830
WIN_LO = 0xFFFF8E773F1A1000
WIN_HI = 0x3F200000

OLD56 = bytes.fromhex("4c8ba7b0000000")

C56 = f"""
    test rdi, rdi
    jz   no_zone
    mov  r12, qword ptr [rdi + 0xb0]
    test r12, r12
    jnz  designed
no_zone:
    movabs r10, {BUMP_SLOT:#x}
    mov  rax, qword ptr [r10]
    test rax, rax
    jnz  b1
    movabs rax, {WIN_LO:#x}
b1:
    lea  r11, [rax + 0x4000]
    cmp  r11d, {WIN_HI:#x}
    ja   designed_fail
    mov  qword ptr [r10], r11
    mov  qword ptr [rbp - 0x40], rax
    jmp  {0xFFFFFFFF9E82B414:#x}
designed:
    jmp  {0xFFFFFFFF9E82B29F:#x}
designed_fail:
    jmp  {0xFFFFFFFF9E82B409:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C56, CAVE56)
print(f"cave56: {len(code):#x}B @ {CAVE56:#x}  hook {S56:#x} ({len(OLD56)}B)")
assert len(code) <= 0x80, "cave56 too big"

img = bytearray(open(IMG, "rb").read())

off = S56 - KTEXT
site = bytes(img[off:off+len(OLD56)])
if site[:1] == b"\xe9":
    rel_expect = CAVE56 - (S56 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S56:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S56:#x}: already hooked to cave56 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD56:
        print(f"FAIL site {S56:#x}: {site.hex()} (expected {OLD56.hex()})"); sys.exit(1)
    hooked = False

off = CAVE56 - KTEXT
cur = bytes(img[off:off+0x80])
if not all(b == 0xCC for b in cur):
    if cur[:3] == bytes.fromhex("4c8ba7"):     # v1 head: mov r12,[rdi+0xb0]
        img[off:off+0x80] = b"\xcc" * 0x80
        print(f"cave {CAVE56:#x}: v1 body found — blanking for rewrite")
    else:
        print(f"FAIL cave {CAVE56:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

md = Cs(CS_ARCH_X86, CS_MODE_64)
insns = list(md.disasm(code, CAVE52 := CAVE56))

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE56 - (S56 + 5)
    off = S56 - KTEXT
    img[off:off+len(OLD56)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD56) - 5)

print("--- cave56 ---")
for i in insns:
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP16#14: zone chunk-import page bump (cave56)")
