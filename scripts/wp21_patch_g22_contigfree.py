#!/usr/bin/env python3
"""WP21 G22 — THE CONTIGFREE BUMP-WINDOW GUARD  [0xa2173198-class]
          (a known blocker between done=1006 and 'Device configuration
           finished.' — the user's WP21 cheat-sheet family)

ROOT CAUSE: contigfree (0x9eff8a50, rdi=addr, rsi=size, rdx=ccp) is fed
residual pointers left over in .data (e.g. [0xa2173198]) — addresses
that belong to no live arena on our cold boot. The fn walks the arena
chunk-hash and per-domain free lists straight into garbage and panics
(the WP19 crash family at 0x9eff8e19/CR2=0x6b).

Our contig memory all comes from the trampoline's carved seed areas —
the bump window [0xffff8e773f000000, 0xffff8e7740000000) (the W1
objects, hash arrays, node chains, vm_dom arrays and the arena pool
up to 0x40000000, seen live as 0xffff8e773f1a3fd0-class pointers in
the earlier GDB rounds). Freeing anything else is by definition a
residual pointer.

FIX — THE LOCAL GUARD (the designed skip): hook contigfree's entry —
rdi inside the bump window -> the original free path runs (the WP13/14
free-epilogue family already answers bump-window frees); anything
outside -> the designed no-op return. Slot 0x9E403D80.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./wp21_kit/wp3_boot/kernel_raw.bin"

SLOT = 0x9E403D80
S = 0x9EFF8A50                         # contigfree entry
OLD = bytes.fromhex("554889e54157")    # push rbp; mov rbp,rsp; push r15 (6B)
CONT = 0xFFFFFFFF9EFF8A56              # push r14 (the next original insn)
LO = 0xFFFF8E773F000000                # bump window low  (DMAP of 0x3F000000)
HI = 0xFFFF8E7740000000                # bump window high (DMAP of 0x40000000)

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

C = f"""
    mov    r11, rdi
    movabs r10, {LO:#x}
    cmp    r11, r10
    jb     skip
    movabs r10, {HI:#x}
    cmp    r11, r10
    jae    skip
    push   rbp
    mov    rbp, rsp
    push   r15
    jmp    {CONT:#x}
skip:
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
print(f"OK WP21-G22: contigfree bump-window guard @0x{S:X} (slot 0x{SLOT:X}) — "
      f"free only [{LO:#x},{HI:#x}), skip every residual pointer")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
