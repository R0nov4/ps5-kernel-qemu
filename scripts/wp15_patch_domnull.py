#!/usr/bin/env python3
"""WP15 #2 — vm_dom block-array NULL guard family (crash 0x9e945c1f, CR2=0x38).

ROOT CAUSE: the per-domain 2MB-block descriptor array pointer
  [vm_dom[i] + 0x10]   (vm_dom @0xa197a3d0, stride 0x28)
is NULL for EVERY domain in our boot image (entry 0's live value
0xffff8e775ee24000 was wiped with the rest of the low-DMAP residue in WP12's
reconstruction; entries 1..N were never non-NULL). The domain checkers compute
  dom = m->domain ([m+0x6b]);  rcx = vm_dom[dom].blocks;
  idx = (m->phys - vm_dom[dom].base) >> 21;   blk = blocks + idx*0x50
and deref blk -> NULL+0x38 / NULL+0x20 fault.

THE CRASH (verified, 1209 lines, after the WP15#1 TAILQ fix):
  pmap_enter(0x9ecd2760) -> 0x9ecd2f61 call 0x9e945bf0(m)
  0x9e945c1f  cmp dword [rcx + rdx + 0x38], 0x80   <<< rcx==0, CR2=0x38
  (m = a fresh vm_page on the zeroed vm_page array: phys [m+0x30]==0 ->
   block 0; the check asks "is this 2MB block full (128 x 16KB pages)?" to
   decide the superpage promotion -> caller 0x9ecd22a0.)

FIX = return EXACTLY what a zeroed block array would return (semantically
identical to seeding, without any array-size/write-collision concerns):
  A) 0x9e945bf0 "block full?"  : [blk+0x38]==0x80?  NULL -> -1 (not full)
     (all 3 callers: 0x9ecd2f61 pmap_enter, 0x9ecd2193 pmap_remove/protect
      family, 0x9ef7b6c3 vm_phys — each 'test eax,eax; jne skip')
  B) 0x9e945bb0 "block empty?" : [blk+0x20] < 1 ?   NULL -> -1 (empty)
     (caller 0x9ef7b46f vm_phys free-page scan)
  C) 0x9e945c30 "take page from block free-list": r8=[blk+0x20]; test; je
     designed-empty-exit 0x9e945cc1 (xor eax,eax)  NULL -> jmp that exit
     (caller 0x9ef7a450 vm_phys page alloc/free)

caves: 25 @0x9E400600 (A), 26 @0x9E400680 (B), 27 @0x9E400700 (C).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE25 = 0x9E400600
CAVE26 = 0x9E400680
CAVE27 = 0x9E400700

SITE_A = 0x9E945C0C; SITE_A_END = 0x9E945C1F; RET_A = 0xFFFFFFFF9E945C1F
SITE_B = 0x9E945BCC; SITE_B_END = 0x9E945BDD; RET_B = 0xFFFFFFFF9E945BDD
SITE_C = 0x9E945C51; SITE_C_END = 0x9E945C67; RET_C = 0xFFFFFFFF9E945C67
EXIT_C = 0xFFFFFFFF9E945CC1     # designed empty-block exit (xor eax,eax; jmp epilogue)

OLD_A = bytes.fromhex("488b4cc11031c048c1ea15488d149248c1e204")          # 19B
OLD_B = bytes.fromhex("488b44c11048c1ea15488d0c9248c1e104")               # 17B
OLD_C = bytes.fromhex("488b7cca1048c1ee15488d34b648c1e6044c8b443720")     # 22B

CAVE25_ASM = f"""
    mov  rcx, qword ptr [rcx + rax*8 + 0x10]
    test rcx, rcx
    jnz  okA
    mov  eax, 0xffffffff
    pop  rbp
    ret
okA:
    xor  eax, eax
    shr  rdx, 0x15
    lea  rdx, [rdx + rdx*4]
    shl  rdx, 4
    jmp  {RET_A:#x}
"""

CAVE26_ASM = f"""
    mov  rax, qword ptr [rcx + rax*8 + 0x10]
    test rax, rax
    jnz  okB
    mov  eax, 0xffffffff
    pop  rbp
    ret
okB:
    shr  rdx, 0x15
    lea  rcx, [rdx + rdx*4]
    shl  rcx, 4
    jmp  {RET_B:#x}
"""

CAVE27_ASM = f"""
    mov  rdi, qword ptr [rdx + rcx*8 + 0x10]
    test rdi, rdi
    jnz  okC
    jmp  {EXIT_C:#x}
okC:
    shr  rsi, 0x15
    lea  rsi, [rsi + rsi*4]
    shl  rsi, 4
    mov  r8, qword ptr [rdi + rsi + 0x20]
    jmp  {RET_C:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

caves = [(CAVE25, asm(CAVE25_ASM, CAVE25), SITE_A, OLD_A, "A"),
         (CAVE26, asm(CAVE26_ASM, CAVE26), SITE_B, OLD_B, "B"),
         (CAVE27, asm(CAVE27_ASM, CAVE27), SITE_C, OLD_C, "C")]

for base, code, site, old, nm in caves:
    print(f"cave{24 + ['A','B','C'].index(nm) + 1} ({nm}): {len(code):#x}B @ {base:#x}  hook {site:#x} ({len(old)}B)")
    assert len(code) <= 0x80, nm

img = bytearray(open(IMG, "rb").read())

def chk(va, old):
    off = va - KTEXT
    if bytes(img[off:off+len(old)]) != old:
        print(f"FAIL {va:#x}: {bytes(img[off:off+len(old)]).hex()} != {old.hex()}"); sys.exit(1)

for base, code, site, old, nm in caves:
    chk(site, old)
    off = base - KTEXT
    if not all(b == 0xCC for b in img[off:off+0x80]):
        print(f"FAIL cave {base:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

def jmp32(site, target, ln):
    off = site - KTEXT
    rel = target - (site + 5)
    img[off:off+ln] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (ln - 5)

md = Cs(CS_ARCH_X86, CS_MODE_64)
for base, code, site, old, nm in caves:
    jmp32(site, base, len(old))
    off = base - KTEXT
    img[off:off+len(code)] = code
    print(f"--- cave {nm} @ {base:#x} ---")
    for i in md.disasm(code, base):
        print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
    o = site - KTEXT
    for i in md.disasm(bytes(img[o:o+5]), 0xFFFFFFFF00000000 + site):
        print(f"  hook {i.address:#x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP15#2: vm_dom block-array NULL guards (caves 25/26/27)")
