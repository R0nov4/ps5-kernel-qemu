#!/usr/bin/env python3
"""WP19 #13 — the window-fault self-healing trap entry (cave93 @0x9E404200).

THE FINAL DMAP STORY (GDB wp19_gdb_c24..c28 + the c25/c27 page-table
  walks): the boot's DMAP for the WP17#4 malloc-window extension is
  fundamentally patchy:
    * [0x3f000000, 0x3f200000) : the trampoline's identity huge page —
      everything below the 0x3f200000 boundary works;
    * [0x3f200000, 0x3f400000) : the trampoline's dump-derived entry
      (0x3ea001e3 — the real PS5's NON-IDENTITY GDDR6 layout), later
      re-installed by the kernel's own pmap code (via its PT-VA aliases,
      invisible to a VA-scoped watchpoint) as a PT-based PDE
      (0xf00000222de063 — the PT at phys 0x222de000 whose PTEs were
      never filled: PTE[0xCE] = 0, PTE[0xD2] = 0);
    * the pmap re-writes that PDE AFTER every one of our huge-page
      re-assertions (cave91 v5/v6, cave92) — a write-vs-write race we
      cannot win from the pop side.
  Symptom: the malloc cursor's objects past 0x3f2ce000 (and the fork1
  child thread page 0x3f2d2000) fault 'supervisor read, page not
  present' — 120 fault/panic/mDBG cycles, the march stalls.

THE FIX (fix-on-fault — immune to any later PDE clobbering): hook the
  TRAP ENTRY itself [0x9e7de0e0, 0x9e7de0e5) (the 4-byte prologue
  'push rbp; mov rbp,rsp' + the first byte of 'push r15'; the cave
  replays the full prologue and re-enters at 0x9e7de0e6):
    rdi = the trapframe; tf+0x80 = the fault VA (CR2);
    if the fault VA is inside the window [0xffff8e773f200000,
    0xffff8e773f800000):
        walk CR3 -> PML4 -> PDPT -> PD;
        write the identity huge-page PDE for the VA's 2MB region
        ((va & ~0x1fffff) | 0x1e3 — the same P|RW|A|D|PS|G pattern as
        the working 0x3f0001e3 entry);
        fall through to the DESIGNED trap handling (the panic print +
        the mDBG dump + the handler's return);
    the instruction retry then walks the fresh PDE and succeeds — the
    fault loop is broken at every occurrence, whatever wrote the PDE
    in between. Non-window traps take the plain designed path.
  Registers: rdi (the trapframe) is preserved; rax/rcx/rdx/r9/r10/r11
  are dead at the trap fn's entry (the IDT stub already saved the full
  register context into the trapframe; the fn's body reloads them from
  0x9e7de0f4 onwards).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE = 0x9E404200
S     = 0x9E7DE0E0                       # the trap entry
PROLOG_CONT = 0xFFFFFFFF9E7DE0E6         # push r14 (after the replayed prologue)
DMAP_LO = 0xFFFF8E7700000000
WIN_LO = 0xFFFF8E773F200000
WIN_HI = 0xFFFF8E773F800000

OLD = bytes.fromhex("554889e541")        # push rbp; mov rbp,rsp; <41>

C = f"""
    mov  rax, qword ptr [rdi + 0x80]
    movabs rcx, {WIN_LO:#x}
    cmp  rax, rcx
    jb   normal_trap
    movabs rcx, {WIN_HI:#x}
    cmp  rax, rcx
    jae  normal_trap
    push rbp
    mov  r10, rax
    mov  rax, cr3
    movabs r11, 0x000ffffffffff000
    and  rax, r11
    movabs rcx, {DMAP_LO:#x}
    add  rax, rcx
    mov  rcx, r10
    shr  rcx, 39
    and  rcx, 0x1ff
    mov  rax, qword ptr [rax + rcx*8]
    and  rax, r11
    movabs rcx, {DMAP_LO:#x}
    add  rax, rcx
    mov  rcx, r10
    shr  rcx, 30
    and  rcx, 0x1ff
    mov  rax, qword ptr [rax + rcx*8]
    and  rax, r11
    movabs rcx, {DMAP_LO:#x}
    add  rax, rcx
    mov  rcx, r10
    shr  rcx, 21
    and  rcx, 0x1ff
    shl  rcx, 3
    add  rcx, rax
    mov  eax, r10d
    and  eax, 0xffe00000
    sub  eax, 0x800000
    or   eax, 0x1e3
    mov  qword ptr [rcx], rax
    pop  rbp
normal_trap:
    push rbp
    mov  rbp, rsp
    push r15
    jmp  {PROLOG_CONT:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C, CAVE)
print(f"cave93 @0x{CAVE:x}: {len(code):#x}B")
assert len(code) <= 0x100, "cave too big"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

off = S - KTEXT
site = bytes(img[off:off+5])
if site[:1] == b"\xe9":
    cur_target = S + 5 + int.from_bytes(site[1:5], "little", signed=True)
    if cur_target != CAVE:
        print(f"FAIL site {S:#x}: E9 -> 0x{cur_target:x} (unexpected)"); sys.exit(1)
    print(f"site {S:#x}: already hooked to cave93 (idempotent)")
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
print("--- window-fault self-healing trap entry (cave93 @0x9E404200) ---")
for i in md.disasm(code, CAVE):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP19#13: window-fault self-healing trap entry (cave93 @0x9E404200)")
