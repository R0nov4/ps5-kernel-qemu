#!/usr/bin/env python3
"""WP22 G37 — THE BZERO/MEMSET NULL-DEST ORACLE GUARD  (G30's family, memset twin)

FRONTIER (G36 boot): the march passes pltauth/sdma/gbase-map (error prints,
tolerated) and dies zeroing the FAILED map object at NULL:

  Fatal trap 12 @0xffffffff9e649024 (rep stosq), CR2=0x0 (WRITE)
    0x9e648ff0  push rbp; mov rbp,rsp
    0x9e648ff4  mov r10, rdi ; add r10, rsi       ; the range check
    ...
    0x9e649024  rep stosq qword ptr [rdi], rax    <<< rdi = NULL

The bzero family entry 0x9e648ff0 gets the same guard G30 gives memcpy:
high-canonical check + the G29 kextract oracle on the dest page; a NULL /
unmapped dest answers 'already zero' semantics — the function returns its
dest (the C memset contract) without touching memory. Valid dests take
the original path byte-identically.

Slot 0x9E404500.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"

S = 0x9E648FF4                          # mov r10,rdi; add r10,rsi (6B, hook 5)
OLD = bytes.fromhex("4989fa4901")       # mov r10,rdi + 1st byte of add
SLOT = 0x9E404500
CONT = 0xFFFFFFFF9E648FFA               # the 'jb' overflow check
KEXTRACT = 0xFFFFFFFF9ECCE330

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
    push   rdi
    push   rsi
    push   rdx
    call   {KEXTRACT:#x}
    test   rax, rax
    pop    rdx
    pop    rsi
    pop    rdi
    jz     bad
    mov    r10, rdi
    add    r10, rsi
    jmp    {CONT:#x}
bad:
    mov    rax, rdi
    pop    rbp
    ret
"""
code = asm(C, SLOT)
assert len(code) <= 0x80, f"stub too big: {len(code):#x}"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

off = S - KTEXT
site = bytes(img[off:off + 5])
rel_expect = (SLOT - (S + 5)).to_bytes(4, "little", signed=True)
if site[:1] == b"\xe9":
    if site[1:5] != rel_expect:
        print(f"FAIL site {S:#x} hooked elsewhere: {site.hex()}"); sys.exit(1)
    hooked = True
else:
    if site != OLD:
        print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
    hooked = False

off = SLOT - KTEXT
cur = bytes(img[off:off + len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    print(f"FAIL slot {SLOT:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)

img[off:off + len(code)] = code
if not hooked:
    off = S - KTEXT
    img[off:off + 5] = b"\xe9" + rel_expect

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP22-G37: bzero/memset NULL-dest oracle guard @0x{S:X} "
      f"(slot 0x{SLOT:X}, stub {len(code):#x}B)")
