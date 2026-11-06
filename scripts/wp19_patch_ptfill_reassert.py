#!/usr/bin/env python3
"""WP19 #12 — the PT-fill install re-assertion (cave92 @0x9E404000).

CASCADE (GDB wp19_gdb_c24/c25, the fault loop at 0xffffffff9e6711fb
  reading 0xffff8e773f2ce068 — 'page not present'):
  The boot's DMAP reality (the page-table walk):
    * [0x3f000000, 0x3f200000) : a 2MB huge page (PDE 0x3f0001e3) — the
      trampoline's W1 mapping — WORKS;
    * [0x3f200000, 0x3f400000) : the residue PDE (0x3ea001e3 — the real
      PS5's GDDR6 layout: VA 0x3f2xxxxxx -> phys 0x3eaxxxxxx, beyond our
      2GB QEMU RAM) -> every access 'page not present'.
  The WP17#4 malloc-window extension [0x3f1a1000, 0x3f740000) reaches
  into these unmapped regions; the boot's cursor crossed 0x3f2ce000 ->
  the fault loop.
  WP19#11v5 (cave91) installs huge-page PDEs for [0x3f200000, 0x3f800000)
  at the PT-page pop — verified live (PDE[505] = 0x3f2001e3 lands and
  persists across pops) — BUT the PT-fill fn (0x9ecd01a0, the SYSINIT
  mapping the window region) then runs its INSTALLER
      0x9ecd038c  call 0x9ecd9040(r15, r13)
  which OVERWRITES PDE[505] with its PT-based entry (0xf00000222de063 —
  the PT at phys 0x222de000 whose PTE[0xCE] is zero) -> the region
  breaks again -> the fault.

THE FIX (re-assert after the designed install): hook the installer call
  [0x9ecd038c, 0x9ecd0391) (5B 'call 0x9ecd9040'):
    replay the original installer call (all its designed side effects);
    then walk CR3 -> PML4 -> PDPT -> PD and re-write the three huge-page
    PDEs (0x3f2001e3 / 0x3f4001e3 / 0x3f6001e3 — the same flag pattern
    as the working 0x3f0001e3);
    jmp 0x9ecd0391 (the designed continuation — r13 is callee-saved and
    untouched; rax/rcx/r11 are dead at that point: 0x9ecd0391 reloads
    rax, rcx is recomputed, r11 is unused in the window).
  The huge mapping is thus the FINAL state after every fill/install —
  the whole window [0x3f1a1000, 0x3f740000) stays identity-mapped.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE = 0x9E404000
S     = 0x9ECD038C                       # the installer call site
INSTALLER = 0xFFFFFFFF9ECD9040           # the original installer
CONT = 0xFFFFFFFF9ECD0391                # movsx rax, [r13+0x2d]
DMAP_LO = 0xFFFF8E7700000000

OLD = bytes.fromhex("e8af8c0000")        # call 0x9ecd9040

C = f"""
    call {INSTALLER:#x}
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
    mov  qword ptr [rax + 0xfa8], 0x3ea001e3
    mov  qword ptr [rax + 0xfb0], 0x3ec001e3
    mov  qword ptr [rax + 0xfb8], 0x3ee001e3
    jmp  {CONT:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C, CAVE)
print(f"cave92 @0x{CAVE:x}: {len(code):#x}B")
assert len(code) <= 0x100, "cave too big"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

off = S - KTEXT
site = bytes(img[off:off+5])
if site[:1] == b"\xe9":
    cur_target = S + 5 + int.from_bytes(site[1:5], "little", signed=True)
    if cur_target != CAVE:
        print(f"FAIL site {S:#x}: E9 -> 0x{cur_target:x} (unexpected)"); sys.exit(1)
    print(f"site {S:#x}: already hooked to cave92 (idempotent)")
    hooked = True
else:
    if site != OLD:
        print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
    hooked = False

off = CAVE - KTEXT
cur = bytes(img[off:off+len(code)])

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE - (S + 5)
    off = S - KTEXT
    img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- PT-fill install re-assertion (cave92 @0x9E404000) ---")
for i in md.disasm(code, CAVE):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP19#12: PT-fill install re-assertion (cave92 @0x9E404000)")
