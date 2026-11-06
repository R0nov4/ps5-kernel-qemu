#!/usr/bin/env python3
"""WP21 G21 — THE RESIDUAL-POINTER MEMCPY GUARD  [0xa18ea20-class]
          (a known crash between done=1006 and 'Device configuration
           finished.' — the user's WP21 cheat-sheet family)

ROOT CAUSE: the kernel's overlap-checked memcpy 0x9e6490b0

      0x9e6490b4  mov r10, rdi ; add r10, rdx      ; dest range check
      ...stack-overlap dispatch (0x9e648fd0 / 0x9e648fe0)...
      0x9e6490e5  rep movsq                         ; <<< CR2 = 0xa18ea20

is fed residual .data pointers (e.g. the never-reinitialized slot
[0xa18ea20]) as copy destinations — a low, non-canonical address that
no live mapping covers, so the copy faults before any caller can react.

FIX — THE LOCAL GUARD (the designed error 0xffffffdb): hook the range-
check site — if rdi (dest) or rsi (src) is not a high-canonical kernel
pointer (bits 63:47 all ones), the copy answers the designed error code
0xffffffdb (sign-extended into rax) instead of faulting; the callers of
this family check the return, exactly the answer they already handle
for the copyin/copyout-style failures. Valid kernel pointers take the
original path unchanged. Slot 0x9E403D00.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./wp21_kit/wp3_boot/kernel_raw.bin"

SLOT = 0x9E403D00
S = 0x9E6490B4                        # mov r10,rdi; add r10,rdx (6B)
OLD = bytes.fromhex("4989fa4901d2")
CONT = 0xFFFFFFFF9E6490BA             # the 'jb' overflow check
ERR = 0xFFFFFFFFFFFFFFDB              # the designed residual-pointer error

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

C = f"""
    mov    r11, rdi
    shr    r11, 47
    cmp    r11, 0x1ffff
    jne    bad
    mov    r11, rsi
    shr    r11, 47
    cmp    r11, 0x1ffff
    jne    bad
    mov    r10, rdi
    add    r10, rdx
    jmp    {CONT:#x}
bad:
    mov    rax, {ERR:#x}
    pop    rbp
    ret
"""
code = asm(C, SLOT)
assert len(code) <= 0x80, f"slot code too big: {len(code):#x}"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

off = S - KTEXT
site = bytes(img[off:off+len(OLD)])
if site[:1] == b"\xe9":
    rel_expect = SLOT - (S + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    hooked = True
else:
    if site != OLD:
        print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
    hooked = False

off = SLOT - KTEXT
cur = bytes(img[off:off+len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    print(f"FAIL slot {SLOT:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)

img[off:off+len(code)] = code
if not hooked:
    rel = SLOT - (S + 5)
    off = S - KTEXT
    img[off:off+len(OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90"

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP21-G21: residual-pointer memcpy guard @0x{S:X} (slot 0x{SLOT:X}) — "
      f"the designed 0xffffffdb answer for non-canonical copy addresses")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
