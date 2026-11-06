#!/usr/bin/env python3
"""WP19 #11 (v3) — the per-CPU PT-page pool's SELF-SUSTAINING pop
                (cave91 @0x9E403E00, replacing v2).

THE FULL STORY (GDB wp19_gdb_c15..c28 + the v1/v2 iterations):
  The fn 0x9ece1e00 pops a PT-page descriptor from the per-CPU pool
  (the static array 0xffffffffa1f37e90, stride 0x68, head at entry+0x20):
      rbx = [entry+0x20]        ; the head descriptor
      rax = [rbx]               ; the 'next' — LIVE-DUMP GARBAGE for the
                                ; early W1-era descriptor (0x8000..4103)
      [entry+0x20] = rax        ; the pop PROPAGATES the garbage
      ... return rbx
      empty: msleep + panic('page table memory exhausted %td')
  v1 (NULL-the-garbage) hit the designed panic: the pool looked empty.
  v2 (always-carve) returned descriptors OUTSIDE the pool's AREA — the
  consumers compute the descriptor's PT-page KVA from its offset inside
  the entry's area (48-byte descriptors: (obj-base)/0x30*0x1000 + the
  area's KVA base — see 0x9ecd0391..0x9ecd0436) — a window carve yields
  a garbage KVA -> the PTE-fill loop (0x9ecd0480) faults at
  0xffff8e80c9530000.
  THE WP18 BEHAVIOR: the boot popped the pool ONCE (the PT-fill fn
  0x9ecd01a0 itself, from the 0x9edfd332 SYSINIT) — the early W1
  descriptor — a VALID object inside the early area whose computed
  PT-page KVA is real W1 memory; no second pop ever happened, so the
  garbage propagation never fired.

THE v3 FIX (the designed-object semantics, KEPT SIMPLE): hook the head
  read [0x9ece1e32, 0x9ece1e37) (5B 'mov rbx, [r13+r14+0x20]'):
    * validate the head (NULL / non-canonical / outside the kernel
      image or the QEMU DMAP RAM) -> the designed empty path
      (jmp 0x9ece1f15 — the msleep + the designed panic);
    * a VALID head -> write the SELF-LINK [head][0] = head: the pop's
      own 'rax = [rbx]; [entry+0x20] = rax' then re-stores the SAME
      head — the pool NEVER drains and the garbage 'next' NEVER
      propagates. Every consumer gets the same VALID early-area
      descriptor (exactly the WP18 outcome), the [+0x20]/[+0x28]
      initializations run on real memory, and the PT-page KVA
      computation reads the entry's REAL early-area fields.
  The early structure's [+0x0] (the garbage 'next') is dead state on
  this boot — overwriting it with the self-link is lossless.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE = 0x9E403E00
S     = 0x9ECE1E32                       # the pool-head read
CONT = 0xFFFFFFFF9ECE1E37                # test rbx, rbx (the designed flow)
EMPTYPATH = 0xFFFFFFFF9ECE1F15           # the designed wait+panic path

KIMG_LO = 0xFFFFFFFF9E3F0000
KIMG_HI = 0xFFFFFFFFA2220000
DMAP_LO = 0xFFFF8E7700000000
DMAP_HI = 0xFFFF8E7780000000

OLD = bytes.fromhex("4b8b5c3520")        # mov rbx, qword ptr [r13 + r14 + 0x20]

C = f"""
    mov  rbx, qword ptr [r13 + r14 + 0x20]
    test rbx, rbx
    jz   bad_head
    movabs rax, {DMAP_LO:#x}
    cmp  rbx, rax
    jb   kimg_check
    movabs rax, {DMAP_HI:#x}
    cmp  rbx, rax
    jb   ok_head
kimg_check:
    movabs rax, {KIMG_LO:#x}
    cmp  rbx, rax
    jb   bad_head
    movabs rax, {KIMG_HI:#x}
    cmp  rbx, rax
    jb   ok_head
    jmp  bad_head
ok_head:
    mov  qword ptr [rbx], rbx








    mov  rax, cr3
    movabs r11, 0x000ffffffffff000
    and  rax, r11
    movabs rcx, {DMAP_LO:#x}
    add  rax, rcx
    mov  rcx, 0xffff8e773f200000
    shr  rcx, 39
    and  rcx, 0x1ff
    mov  rax, qword ptr [rax + rcx*8]
    and  rax, r11
    movabs rcx, {DMAP_LO:#x}
    add  rax, rcx
    mov  rcx, 0xffff8e773f200000
    shr  rcx, 30
    and  rcx, 0x1ff
    mov  rax, qword ptr [rax + rcx*8]
    and  rax, r11
    movabs rcx, {DMAP_LO:#x}
    add  rax, rcx
    mov  rcx, qword ptr [rax + 0xfa8]
    test rcx, 1
    jz   no_pt_a
    test cl, 0x80
    jnz  no_pt_a
    and  rcx, r11
    movabs rdx, {DMAP_LO:#x}
    add  rcx, rdx
    movrdx,0x3ea000e3
    mov  r9d, 512
fill_a:
    mov  qword ptr [rcx], rdx
    add  rcx, 8
    add  rdx, 0x1000
    dec  r9d
    jnz  fill_a
no_pt_a:
    mov  qword ptr [rax + 0xfa8], 0x3ea001e3
    mov  qword ptr [rax + 0xfb0], 0x3ec001e3
    mov  qword ptr [rax + 0xfb8], 0x3ee001e3

    jmp  {CONT:#x}
bad_head:
    jmp  {EMPTYPATH:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C, CAVE)
print(f"cave91 v3 @0x{CAVE:x}: {len(code):#x}B")
assert len(code) <= 0x1f0, "cave too big"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

off = S - KTEXT
site = bytes(img[off:off+5])
if site[:1] == b"\xe9":
    cur_target = S + 5 + int.from_bytes(site[1:5], "little", signed=True)
    if cur_target != CAVE:
        print(f"FAIL site {S:#x}: E9 -> 0x{cur_target:x} (unexpected)"); sys.exit(1)
    print(f"site {S:#x}: already hooked to cave91 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD:
        print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
    hooked = False

off = CAVE - KTEXT
cur = bytes(img[off:off+len(code)])
ours_before = cur[:5] == OLD or cur[:1] == b"\x55" or cur[:3] == bytes.fromhex("4885db")
if not all(b == 0xCC for b in cur) and cur != code and not ours_before:
    print(f"FAIL cave {CAVE:#x} not pristine CC / ours: {cur[:16].hex()}"); sys.exit(1)

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE - (S + 5)
    off = S - KTEXT
    img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- per-CPU PT-page pool self-sustaining pop (cave91 v3 @0x9E403E00) ---")
for i in md.disasm(code, CAVE):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP19#11: per-CPU PT-page pool self-sustaining pop (cave91 v3 @0x9E403E00)")
