#!/usr/bin/env python3
"""WP15 #3 — W1 bump step 0x78 -> 0xF0 + exhaustion bound (plinks.q panic).

ROOT CAUSE (GDB-verified, assert 0x9ef7c2fb in vm_page_dequeue 0x9ef7c200):
  panic: Bad link in "plinks.q", elm != next->prev,
         elm=0xffff8e773f0100f0 next=0xffff8e773f000008 next->prev=0
  The W1 bump-allocator cave (WP9, hook vm_page_alloc@0x9EA05730 -> cave
  0x9EE30100) advances its bump pointer by a FIXED 0x78 — but the objects
  it hands out are vm_pages whose fields reach +0x78 (plinks.q pair
  {next@+0x70, prev@+0x78} — the W6-tail list links, seen in the insert at
  0x9ecd36eb..0x9ecd3715). GDB state at the panic:
    [0x3F000000] = 0x3F010168        <- W1 bump = 3 allocations done
    [0x3F000008] = 0xffff8e773f010078<- W6-list head slot = W1#1
    m0 = W1#0 = 0x3F010000, X = W1#1 = 0x3F010078, m1 = W1#2 = 0x3F0100F0
  X's W6-list insert wrote [X+0x78] = tail-anchor = 0x3F000008 — and
  X+0x78 = 0x3F0100F0 = m1's base -> m1->plinks.q.tqe_next corrupted ->
  the dequeue assert fires (caller chain: vm_page_startup loop 0x9e8f3eee
  -> 0x9ef7a678 -> 0x9ef78fc2 -> vm_page_dequeue(m1)).

FIX: rewrite the W1 cave with
  - step 0xF0 (covers the vm_page struct with margin; observed fields
    reach +0x78, so 0x80 is the minimum — 0xF0 adds safety for unobserved
    fields; W1 area [0x3F010000,0x3F100000) = 960KB -> 4096 objects)
  - exhaustion bound: bump >= 0x3F0F0000 -> return NULL (the callers'
    designed failure paths: 'test rax,rax; je ...')
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

W1_CAVE = 0x9EE30100
W1_END  = 0x9EE30180          # reserved area (WP9 assert)
BUMP_SLOT = 0xFFFF8E773F000000
DMAP_BASE = 0xFFFF8E7700000000
W1_LO = 0x3F010000
W1_HI = 0x3F0F0000            # just below the chunk-hash arrays @0x3F100000

W1_ASM = f"""
    movabs rax, {BUMP_SLOT:#x}
    mov  rcx, qword ptr [rax]
    test rcx, rcx
    jnz  have
    mov  ecx, {W1_LO:#x}
have:
    cmp  ecx, {W1_HI:#x}
    jae  exhausted
    movabs rdx, {DMAP_BASE:#x}
    lea  r8, [rcx + 0xf0]
    mov  qword ptr [rax], r8
    add  rdx, rcx
    mov  qword ptr [rdx + 0x30], rcx
    mov  rax, rdx
    ret
exhausted:
    xor  eax, eax
    ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(W1_ASM, W1_CAVE)
if not enc:
    print("ASM FAILED"); sys.exit(1)
new_code = bytes(enc)
print(f"W1 cave (new): {len(new_code):#x}B @ {W1_CAVE:#x}")
assert W1_CAVE + len(new_code) <= W1_END, "W1 cave overruns its reserved area"

img = bytearray(open(IMG, "rb").read())
off = W1_CAVE - KTEXT

# the OLD cave must be there (verify by its known head/tail bytes)
OLD_HEAD = bytes.fromhex("48b80000003f778effff")       # movabs rax, 0xffff8e773f000000
OLD_TAIL = bytes.fromhex("4889d0c3")                    # mov rax, rdx ; ret
if bytes(img[off:off+len(OLD_HEAD)]) != OLD_HEAD:
    print(f"FAIL: old W1 head not found: {bytes(img[off:off+len(OLD_HEAD)]).hex()}")
    sys.exit(1)
tail_off = 0x2F  # old 'mov rax,rdx; ret' at 0x9EE3012F (4B ending at 0x33)
if bytes(img[off+tail_off:off+tail_off+len(OLD_TAIL)]) != OLD_TAIL:
    print(f"FAIL: old W1 tail not found: {bytes(img[off+tail_off:off+tail_off+len(OLD_TAIL)]).hex()}")
    sys.exit(1)
# the old cave bytes we overwrite span [0, 0x33); everything past must be dead
old_len = 0x33
print("old W1 cave assertions OK")

# blank the old cave area (fill int3 up to the new code end), then write
end = max(old_len, len(new_code))
img[off:off+end] = b"\xcc" * end
img[off:off+len(new_code)] = new_code

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- new W1 cave ---")
for i in md.disasm(new_code, W1_CAVE):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP15#3: W1 bump step 0x78 -> 0xF0 + exhaustion bound (NULL)")
