#!/usr/bin/env python3
"""WP22 G33 — THE DUMP-NOTIFIER NULL-CTX GUARD

FRONTIER (G31v3 boot): the march now passes the whole record-copy family
(the DMAP scratch region works — the read-backs succeed!) and dies in the
hardware notifier:

  Fatal trap 12 @0xffffffff9e825aae, CR2=0x10 (READ)
    0x9e825aa0  push rbp; mov rbp,rsp; push r15/r14/r13/r12/rbx/rax
    0x9e825aae  mov rcx, qword ptr [rdi + 0x10]      <<< rdi = ctx = NULL

The notifier's ctx comes from the global [0xA18E9FD0] (loaded at
0x9e825a1d) — the dump device context, never initialized on our boot
(no such hardware). The caller already tolerates failure:
    0x9e825a36  call 0x9e825aa0
    0x9e825a42  mov r15d, eax
    0x9e825a4e  test r15d, r15d
    0x9e825a51  je 0x9e825a8e                       ; the clean epilogue

FIX — THE DESIGNED ZERO ANSWER: hook the faulting instruction's 5-byte
window (mov rcx,[rdi+0x10] + 1 byte of 'mov rax,rdx'); the stub replays
both instructions for a live ctx, and for ctx == NULL answers 0 ('notify
failed') via the function's own unwind sequence (pop rax/rbx/r12-r15/rbp;
ret) — the caller then takes its own designed skip path.
Slot 0x9E404400.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"

S = 0x9E825AAE                          # the faulting 'mov rcx,[rdi+0x10]'
OLD = bytes.fromhex("488b4f1048")       # mov rcx,[rdi+0x10] + 1st byte of mov rax,rdx
SLOT = 0x9E404400
CONT = 0xFFFFFFFF9E825AB5               # after 'mov rax,rdx'

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
    mov    rcx, qword ptr [rdi + 0x10]
    mov    rax, rdx
    jmp    {CONT:#x}
zero:
    xor    eax, eax
    pop    rax
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
print(f"OK WP22-G33: dump-notifier NULL-ctx guard @0x{S:X} "
      f"(slot 0x{SLOT:X}, stub {len(code):#x}B) — the designed zero answer")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
