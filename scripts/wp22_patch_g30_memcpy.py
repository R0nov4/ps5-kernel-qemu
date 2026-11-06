#!/usr/bin/env python3
"""WP22 G30 — THE MAPPED-DEST/SRC MEMCPY GUARD  (G21's family, extended)

NEW FRONTIER (found by the G29v2 confirmation boot): the march now passes
'[MP1] Create rlc dump' (the self-map crash is GONE) and dies in the same
memcpy family G21 guards — but with a CANONICAL-yet-UNMAPPED residual
pointer:

  Fatal trap 12 @0xffffffff9e6490e5 (rep movsq), CR2=0xffffff8098beb800
  supervisor WRITE, page not present

G21 (slot 0x9E403D00) only rejects NON-canonical rdi/rsi; the new garbage
is high-canonical so it slips through and the rep movsq faults.

FIX — THE ORACLE GUARD (the user's cheat-sheet designed answer
'residual pointer crash ... -> return 0xffffffdb', upgraded): redirect
the G21 hook to a new slot; after the canonical checks, call the G29
kextract stub (0x9ECCE330 — now a fault-free software page walk) on the
DEST and on the SRC: a zero answer means the page is UNMAPPED -> the
copy answers the designed 0xffffffffffffffdb error exactly like G21's
non-canonical path. Mapped pointers take the original path unchanged.

Provably non-regressive: any copy that previously SURVIVED had both
pages mapped -> kextract != 0 -> the guard passes it. The guard only
rejects copies that would have faulted anyway.

Slot 0x9E404180 (CC-verified span [0x9E404180, 0x9E404400)).
The G21 stub at 0x9E403D00 becomes dead code (hook redirected).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"

HOOK = 0x9E6490B4                       # the G21 hook site (mov r10,rdi; add r10,rdx)
G21_SLOT = 0x9E403D00
SLOT = 0x9E404180
SPAN = 0x280                            # [0x9E404180, 0x9E404400)
CONT = 0xFFFFFFFF9E6490BA               # the 'jb' overflow check
KEXTRACT = 0xFFFFFFFF9ECCE330           # the G29 software-walk kextract
ERR = 0xFFFFFFFFFFFFFFDB                # the designed residual-pointer error

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
    push   rdi
    push   rsi
    push   rdx
    call   {KEXTRACT:#x}
    test   rax, rax
    pop    rdx
    pop    rsi
    pop    rdi
    jz     bad
    push   rdi
    push   rsi
    push   rdx
    mov    rdi, rsi
    call   {KEXTRACT:#x}
    test   rax, rax
    pop    rdx
    pop    rsi
    pop    rdi
    jz     bad
    mov    r10, rdi
    add    r10, rdx
    jmp    {CONT:#x}
bad:
    movabs rax, {ERR:#x}
    pop    rbp
    ret
"""
code = asm(C, SLOT)
assert len(code) <= SPAN - 0x40, f"stub too big: {len(code):#x}"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

# --- hook site: currently points at G21's slot (or already at ours) ---
off = HOOK - KTEXT
site = bytes(img[off:off + 5])
rel_g21 = (G21_SLOT - (HOOK + 5)).to_bytes(4, "little", signed=True)
rel_new = (SLOT - (HOOK + 5)).to_bytes(4, "little", signed=True)
if site[:1] == b"\xe9" and site[1:5] == rel_new:
    pass                                # already redirected (idempotent)
elif site[:1] == b"\xe9" and site[1:5] == rel_g21:
    img[off:off + 5] = b"\xe9" + rel_new    # redirect G21's hook to G30
elif site == bytes.fromhex("4989fa4901d2"):
    img[off:off + 5] = b"\xe9" + rel_new    # pre-G21 image (robustness)
else:
    print(f"FAIL hook {HOOK:#x} unexpected: {site.hex()}"); sys.exit(1)

# --- slot: must be pristine CC (or our own code, idempotent) ---
off = SLOT - KTEXT
cur = bytes(img[off:off + len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    print(f"FAIL slot {SLOT:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)

img[off:off + len(code)] = code

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP22-G30: mapped-dest/src memcpy oracle guard — hook 0x{HOOK:X} "
      f"redirected to slot 0x{SLOT:X} (stub {len(code):#x}B), "
      f"kextract-oracle + the designed 0xffffffdb answer")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
