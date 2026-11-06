#!/usr/bin/env python3
"""WP22 G34 — THE SBL-SERVICE NULL-ARG GUARD

FRONTIER (G33 boot): the march now prints the whole SBL service layer
(sceSblServiceMailbox error family) and dies at

  Fatal trap 12 @0xffffffff9e8da8be, CR2=0x64 (READ)
    0x9e8da8b0  push rbp; mov rbp,rsp; push r15/r14/r13/r12/rbx; push rax
    0x9e8da8be  cmp dword ptr [rdi + 0x64], 0      <<< rdi = NULL

The caller passed a NULL context. The function's own 'not found' paths
return NULL (xor r14d; mov rax,r14) and its unwind discards the pushed
rax slot via `add rsp, 8` — the designed NULL answer.

FIX: hook the 5-byte window at the faulting cmp; stub: rdi == NULL ->
unwind + return 0 (the designed 'nothing found' answer); live rdi ->
replay 'cmp [rdi+0x64],0' + 'mov rbx,rdi' and jump back to 0x9e8da8c5.
Slot 0x9E404480.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"

S = 0x9E8DA8BE
OLD = bytes.fromhex("837f64004 8".replace(" ", ""))
SLOT = 0x9E404480
CONT = 0xFFFFFFFF9E8DA8C5

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

C = f"""
    test   rdi, rdi
    jz     zero
    cmp    dword ptr [rdi + 0x64], 0
    mov    rbx, rdi
    jmp    {CONT:#x}
zero:
    xor    eax, eax
    add    rsp, 8
    pop    rbx
    pop    r12
    pop    r13
    pop    r14
    pop    r15
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
print(f"OK WP22-G34: SBL-service NULL-arg guard @0x{S:X} "
      f"(slot 0x{SLOT:X}, stub {len(code):#x}B) — the designed NULL answer")
