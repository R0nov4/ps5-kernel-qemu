#!/usr/bin/env python3
"""WP15 #4 — vm_page_dequeue never-enqueued guard (crash 0x9ef7c269, CR2=0x0).

ROOT CAUSE: after the W1 step fix, the boot reaches
  vm_page_dequeue (0x9ef7c200) with a FRESH W1 vm_page whose plinks.q
  = {tqe_next=0, tqe_prev=0} — the page was never enqueued in any page
  queue (the designed flow: 0x9EA05730 returns a page FROM the free
  queue; our W1 bump-allocator creates brand-new zero pages instead).
    0x9ef7c244  rax = [rbx]           ; next = 0
    0x9ef7c24a  je 0x9ef7c265         ; tail path
    0x9ef7c265  rax = [rbx+8]         ; prev = 0
    0x9ef7c269  cmp [rax], rbx        ; <<< CRASH (rax==0)
  (caller chain: vm_page_startup loop -> 0x9ef7a678 -> 0x9ef78fc2 ->
   dequeue(m); the alloc path dequeues the page it just got from W1.)

FIX: cave28 @0x9E400780 — entry guard on the dequeue:
    [rdi+8] (m->plinks.q.tqe_prev) == 0 -> the page is not in any queue
    -> plain 'ret' (no lock has been taken yet — the function only locks
       at 0x9ef7c23b; the designed epilogue tail-jmps to the unlock, so
       the early exit must NOT unlock). A no-op removal for a page that
       was never counted is semantically exact.
    non-zero -> replay the 6 replaced prologue bytes (push rbp; mov
       rbp,rsp; push r15) and continue at 0x9ef7c206 (push r14).
  Protects all 9 callers (0x9eaf70bd, 0x9ef78fc2, 0x9ef7946c, ...).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE28  = 0x9E400780
SITE    = 0x9EF7C200
SITE_END = 0x9EF7C206
CONT_F  = 0xFFFFFFFF9EF7C206       # push r14 (after the 6 replaced bytes)

SITE_OLD = bytes.fromhex("554889e54157")     # push rbp; mov rbp,rsp; push r15 (6B)

CAVE28_ASM = f"""
    cmp  qword ptr [rdi + 8], 0
    jne  go
    ret
go:
    push rbp
    mov  rbp, rsp
    push r15
    jmp  {CONT_F:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE28_ASM, CAVE28)
if not enc:
    print("ASM FAILED"); sys.exit(1)
cave28 = bytes(enc)
print(f"cave28: {len(cave28):#x}B @ {CAVE28:#x}")
assert len(cave28) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = SITE - KTEXT
if bytes(img[off:off+len(SITE_OLD)]) != SITE_OLD:
    print(f"FAIL site {SITE:#x}: {bytes(img[off:off+len(SITE_OLD)]).hex()} != {SITE_OLD.hex()}")
    sys.exit(1)
off = CAVE28 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave28 {CAVE28:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

# hook: jmp cave28 over the 6 prologue bytes
off = SITE - KTEXT
rel = CAVE28 - (SITE + 5)
img[off:off+len(SITE_OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90"

# write cave
off = CAVE28 - KTEXT
img[off:off+len(cave28)] = cave28

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- site 0x9ef7c200 ---")
o = SITE - KTEXT
for i in md.disasm(bytes(img[o:o+6]), 0xFFFFFFFF9EF7C200):
    print(f"  {i.address:#x}  {i.bytes.hex():<12} {i.mnemonic} {i.op_str}")
print("--- cave28 ---")
for i in md.disasm(cave28, CAVE28):
    print(f"  {i.address:#x}  {i.bytes.hex():<16} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP15#4: vm_page_dequeue never-enqueued guard (cave28 @0x9E400780)")
