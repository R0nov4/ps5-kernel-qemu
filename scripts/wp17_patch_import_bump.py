#!/usr/bin/env python3
"""WP17 #9 — the zone-import failure bump (cave69 @0x9E401C80).

ROOT CAUSE (GDB wp17_gdb_c9):
  The zone-create flow (0x9ec2d063: heap_alloc 0x9e82b0e0 -> the chunk
  alloc 0x9e82b260 with the DESIGNED STATIC zone 0xa18eaf40) calls the
  zone's REAL import thunk (0x9e65a700 -> 0x9e82f8a0):
    0x9e82b2c3  call r12(rdi=[zone+0xc0], rsi=&[rbp-0x40], 1, flags)
    0x9e82b2c6  cmp eax, 1
    0x9e82b2c9  jne 0x9e82b409          ; the designed fail -> NULL
  On this boot the real import returns eax=0 EVERY retry (the zone's
  page-supply machinery is the never-initialized family) -> the heap
  alloc returns NULL -> the caller's zone object is NULL ->
  'mov qword ptr [rax], -1' at 0x9ec2d09c writes [NULL] -> CR2=0.

FIX — the import-failure bump (the cave56-v2 pattern applied to the
  import RESULT instead of the import SLOT): hook the fail branch
  [0x9e82b2c9, 0x9e82b2cf) (6B 'jne 0x9e82b409'):
    eax == 1            -> the designed success continuation 0x9e82b2cf
    eax != 1 (the fail) -> bump one 16KB page from the SHARED window
                           (state @0x3F1A0830, ceiling 0x3F740000 — the
                           WP17#4 extension), [rbp-0x40] := page,
                           rax := page, jump cave56's return tail
                           0x9e82b414 (the r13 balance check + epilogue)
    window exhaustion   -> the designed fail 0x9e82b409
  The zone-create family now always gets real memory for its chunks.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE69 = 0x9E401C80
S69, S69E = 0x9E82B2C9, 0x9E82B2CF          # jne 0x9e82b409 (6B)
OK69 = 0xFFFFFFFF9E82B2CF                    # the designed success continuation
FAIL69 = 0xFFFFFFFF9E82B409                  # the designed fail
TAIL69 = 0xFFFFFFFF9E82B414                  # cave56's return tail (rax preserved)

BUMP_SLOT = 0xFFFF8E773F1A0830
WIN_LO = 0xFFFF8E773F1A1000
WIN_HI = 0x3F740000

OLD69 = bytes.fromhex("0f853a010000")       # jne 0x9e82b409

C69 = f"""
    cmp  eax, 1
    je   designed_ok
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
    jmp  {TAIL69:#x}
designed_ok:
    jmp  {OK69:#x}
designed_fail:
    jmp  {FAIL69:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C69, CAVE69)
print(f"cave69: {len(code):#x}B @ {CAVE69:#x}  hook {S69:#x} (6B)")
assert len(code) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = S69 - KTEXT
site = bytes(img[off:off+len(OLD69)])
if site[:1] == b"\xe9":
    rel_expect = CAVE69 - (S69 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S69:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S69:#x}: already hooked to cave69 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD69:
        print(f"FAIL site {S69:#x}: {site.hex()} != {OLD69.hex()}"); sys.exit(1)
    hooked = False

off = CAVE69 - KTEXT
cur = bytes(img[off:off+len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    print(f"FAIL cave {CAVE69:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)
print("site + cave assertions OK")

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE69 - (S69 + 5)
    off = S69 - KTEXT
    img[off:off+len(OLD69)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90"

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave69 (import-failure bump) ---")
for i in md.disasm(code, CAVE69):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP17#9: zone-import failure bump (cave69)")
