#!/usr/bin/env python3
"""WP15 #1 — TAILQ lazy-init for pmap_enter's pv-list insert (crash 0x9ecd2d0c).

USER ROOT CAUSE (verified on the user's machine + our local QEMU, 1209 lines):
  Crash 0xffffffff9ecd2d0c (CR2=0x0 WRITE, proc0/SceSwapper, rsp a2228850)
  is inside pmap_enter (fn 0x9ecd2760 — assert strings 'pmap_enter: invalid
  page directory va=%#lx' @0x9f7a4872 / 'accessing unloaded FMEM container'
  @0x9f750bdd / 'Bad link in "pv_next"' @0x9f6b35a1):
    0x9ecd2d00  mov rcx, [r13+0x40]     ; rcx = head->tqh_last   (0 on cold page!)
    0x9ecd2d04  add rax, 8              ; rax = &elm->tqe_next
    0x9ecd2d08  mov [rdx+0x10], rcx     ; elm->tqe_prev = tqh_last
    0x9ecd2d0c  mov [rcx], rdx          ; *tqh_last = elm  <<< CRASH (rcx==0)
    0x9ecd2d0f  mov [r13+0x40], rax     ; head->tqh_last = &elm->tqe_next
    0x9ecd2d13  inc dword [r13+0x48]    ; count++
  r13 = the vm_page argument (rdx of pmap_enter, from caller 0x9e8f3d80's
  loop = 0x9ef7a1a0 lookup on the freshly arena-allocated vm_page array).
  The vm_page array lives on RAW ZERO pages: md.pv_list = {tqh_first@+0x38,
  tqh_last@+0x40, pv_count@+0x48} has tqh_first=NULL (fine) but tqh_last=NULL
  instead of the TAILQ_INIT self-anchor &tqh_first -> first insert NULL-writes.

FIX (user-specified): cave24 @0x9E400500 (0xCC island, right after cave23):
    mov rcx, [r13+0x40]
    test rcx, rcx
    jnz ok
    lea rcx, [r13+0x38]        ; lazy TAILQ_INIT: tqh_last := &tqh_first
  ok:
    add rax, 8
    mov [rdx+0x10], rcx
    mov [rcx], rdx
    mov [r13+0x40], rax
    jmp 0xffffffff9ecd2d13
  The list becomes fully consistent after the first insert (tqh_first=elm,
  elm->tqe_prev=&tqh_first, tqh_last=&elm->tqe_next) — all later inserts and
  all removes (helper 0x9ece3550 walks tqh_first; empty -> xor eax,eax; ret)
  work unchanged. Register contract = exactly the original 5 instructions.

NEIGHBOR AUDIT (user-requested): full scan of the pmap region 0x9ecc0000..
0x9ed10000 found 11 TAILQ_INSERT_TAIL candidates; besides this site, 4 more
use the SAME zero-able +0x40 head layout (0x9ecd5581, 0x9ecd7322, 0x9ecda7fd,
0x9ece24ff) — they are NOT on the current boot path (handled reactively in
the crash loop if reached).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE24  = 0x9E400500            # lazy-init TAILQ insert (user-specified)
SITE    = 0x9ECD2D00            # mov rcx,[r13+0x40]  (insert head load)
SITE_F  = 0xFFFFFFFF9ECD2D00
RET_F   = 0xFFFFFFFF9ECD2D13    # inc dword [r13+0x48]

SITE_OLD = bytes.fromhex("498b4d404883c00848894a1048891149894540")  # 19B

CAVE24_ASM = f"""
    mov  rcx, qword ptr [r13 + 0x40]
    test rcx, rcx
    jnz  ok
    lea  rcx, [r13 + 0x38]
ok:
    add  rax, 8
    mov  qword ptr [rdx + 0x10], rcx
    mov  qword ptr [rcx], rdx
    mov  qword ptr [r13 + 0x40], rax
    jmp  {RET_F:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE24_ASM, CAVE24)
if not enc:
    print("ASM FAILED"); sys.exit(1)
cave24 = bytes(enc)
print(f"cave24: {len(cave24):#x}B @ {CAVE24:#x}")
assert len(cave24) <= 0x100

img = bytearray(open(IMG, "rb").read())

def chk(va, old, ln=None):
    off = va - KTEXT
    ln = ln or len(old)
    if bytes(img[off:off+ln]) != old:
        print(f"FAIL {va:#x}: {bytes(img[off:off+ln]).hex()} != {old.hex()}"); sys.exit(1)

chk(SITE, SITE_OLD)
off = CAVE24 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x100]):
    print(f"FAIL cave24 {CAVE24:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

# --- patch site: jmp cave24 (5B) + NOP pad ---
def jmp32(site, target, ln):
    off = site - KTEXT
    rel = target - (site + 5)
    img[off:off+ln] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (ln - 5)

jmp32(SITE, CAVE24, len(SITE_OLD))

# --- write cave ---
off = CAVE24 - KTEXT
img[off:off+len(cave24)] = cave24

# --- verify with capstone ---
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- site 0x9ecd2d00 ---")
o = SITE - KTEXT
for i in md.disasm(bytes(img[o:o+len(SITE_OLD)]), SITE_F):
    print(f"  {i.address:#x}  {i.bytes.hex():<14} {i.mnemonic} {i.op_str}")
print("--- cave24 ---")
for i in md.disasm(cave24, CAVE24):
    print(f"  {i.address:#x}  {i.bytes.hex():<20} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP15#1: pmap_enter pv-list TAILQ lazy-init (cave24 @0x9E400500)")
