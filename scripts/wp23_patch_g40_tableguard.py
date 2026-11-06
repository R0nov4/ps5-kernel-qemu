#!/usr/bin/env python3
"""WP23 G40 — THE TRIE-BLOCK ORACLE GUARD  (user boot1 crash site)

User's laptop boot (G26 disarmed by hand): the march passes the mca
taskq / camera / acm entries (graceful failure prints) and dies at

  Fatal trap 12 @ 0xffffffff9eb6e9e7, CR2 = 0xffffff809a00effe (READ)
  current process = 0 (SceSwapper)  — still inside the sysinit walk

The crash fn 0x9eb6e9d0 (args: table rdi, 11+bit index esi, out ptrs
rdx/rcx/r8; returns an in-block pointer):
    0x9eb6e9d4  mov eax, esi
    0x9eb6e9d6  shl esi, 0xa            ; (idx & 0x7ff) << 10
    0x9eb6e9d9  shr eax, 0xb            ; sub-table selector
    0x9eb6e9dc  and esi, 0x1ffc00
    0x9eb6e9e2  mov rax, [rdi + rax*8 + 0x20]      ; sub-table base
    0x9eb6e9e7  movzx edi, word [rax + rsi + 0x3fe]  <<< CRASH
    ... u16 reads at +0x3fc / +0x3fa, returns block + 0x3fa - val*2

The sub-table base loaded from the table is 0xffffff809a00xxxx —
canonical, but the page is NOT mapped in this boot (real-hardware
table our emulation never maps; the table read itself succeeds, so
the fault is exactly the block deref).

GUARD (the G30/G37 oracle-guard family): hook the entry 0x9eb6e9d0;
the stub (1) replays the prologue, (2) recomputes the index math,
(3) probes BOTH the table-read address and the faulting block page
with the G29 CR3-walk oracle 0x9ECCE330 (pure page-table walk through
the DMAP, never faults, answers 0 for unmapped VAs), (4) on a bad
probe answers with EMPTY-ENTRY semantics: out-params zeroed, return
pointer aimed at a private zero-filled 0x400 fake block at 0x9E404800
(mapped, all zero) so the caller's chained walks (0x9e7b2e10 etc.)
read zeros instead of faulting; (5) on good probes it restores
eax = idx and rejoins the original stream at 0x9eb6e9d6
byte-identically.

Slot 0x9E404600 (stub) + fake zero block 0x9E404800..0x9E404BFF.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"

S = 0x9EB6E9D0                            # fn entry (6B insn prefix)
OLD = bytes.fromhex("554889e589f0")       # push rbp; mov rbp,rsp; mov eax,esi
CONT = 0xFFFFFFFF9EB6E9D6                 # rejoin point (shl esi,0xa)
SLOT = 0x9E404600
KEXTRACT = 0xFFFFFFFF9ECCE330             # G29 CR3-walk oracle
FAKE = 0x9E404800                         # zero-filled 0x400 fake block
FAKE_RET = 0xFFFFFFFF9E404BFA             # FAKE + 0x3fa

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

C = f"""
    push rbp
    mov  rbp, rsp
    mov  eax, esi
    mov  r11d, esi
    shr  r11d, 11
    lea  r10, [rdi + r11*8 + 0x20]
    mov  r11, r10
    shr  r11, 47
    cmp  r11, 0x1ffff
    jne  bad
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    mov  rdi, r10
    call {KEXTRACT:#x}
    test rax, rax
    pop  r8
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    jz   bad
    mov  r11d, esi
    shr  r11d, 11
    mov  rax, qword ptr [rdi + r11*8 + 0x20]
    mov  r11d, esi
    shl  r11d, 10
    and  r11d, 0x1ffc00
    mov  r10, rax
    add  r10, r11
    mov  r11, r10
    add  r11, 0x3fe
    shr  r11, 47
    cmp  r11, 0x1ffff
    jne  bad
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    lea  rdi, [r10 + 0x3fe]
    call {KEXTRACT:#x}
    test rax, rax
    pop  r8
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    jz   bad
    mov  eax, esi
    jmp  {CONT:#x}
bad:
    xor  eax, eax
    test rdx, rdx
    je   s1
    mov  dword ptr [rdx], 0
s1:
    test rcx, rcx
    je   s2
    mov  dword ptr [rcx], 0
s2:
    test r8, r8
    je   s3
    mov  dword ptr [r8], 0
s3:
    movabs rax, {FAKE_RET:#x}
    pop  rbp
    ret
"""
code = asm(C, SLOT)
assert len(code) <= 0xF0, f"stub too big: {len(code):#x}"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

off = S - KTEXT
site = bytes(img[off:off + len(OLD)])
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

off = FAKE - KTEXT
cur = bytes(img[off:off + 0x400])
if not all(b == 0xCC for b in cur):
    print(f"FAIL fake block {FAKE:#x} not pristine CC"); sys.exit(1)

img[SLOT - KTEXT:SLOT - KTEXT + len(code)] = code
img[FAKE - KTEXT:FAKE - KTEXT + 0x400] = b"\x00" * 0x400
if not hooked:
    off = S - KTEXT
    img[off:off + len(OLD)] = b"\xe9" + rel_expect + b"\x90"

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP23-G40: trie-block oracle guard @0x{S:X} "
      f"(slot 0x{SLOT:X}, stub {len(code):#x}B, fake zero block 0x{FAKE:X})")
