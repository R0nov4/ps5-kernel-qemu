#!/usr/bin/env python3
"""WP19 #4 — the kstack stack-VA bump-window allocator (cave83 @0x9E402F00).

CASCADE (GDB wp19_gdb_c4): proc_setup allocates the actual kernel stack
  via vm_map_find:
      0x9e92a634  call 0x9e8f33b0            ; vm_map_find(kernel_map, size, 0x2001)
  0x9e8f33b0 reads the map pointer from a global and calls the
  map-allocation engine 0x9e9d6730. The kernel_map's free-space state is
  LIVE-DUMP RESIDUE (the real PS5's 16GB GDDR6 cursor): the call returns
  DMAP(0xC69EC000) = physical 3.3GB — the QEMU PCI hole (2GB RAM):
      * the kstack zeroer 0x9eccedb0 writes through the DMAP alias ->
        silently dropped (unassigned PCI-hole writes);
      * the PCB (cpu_thread_alloc: pcb = kstack_top-0x1c0) lives in the
        black hole -> reads come back as garbage -> a real context
        switch to the thread would load a garbage rsp.
  The march survives (no fault) but the new thread's stack is a mirage.

THE v1 BUG (found live, GDB wp19_gdb_c6 trap-catch): v1 loaded the carve
  size with 'mov rdi, [rsp]' — reading the SAVED vm_map_find RESULT
  (~0xffff8e74c69ec000, 3.3GB) instead of the SIZE. 'add r11, rdi' then
  WRAPPED modulo 2^64; the wrapped r11 (0xffff1cec...-style, non-canonical)
  is UNSIGNED-LESS than CEIL, so the bounds check passed and the cave
  stored the GARBAGE cursor. The next malloc(0x38) (the ioapic intr-event
  creation) served from it -> rax = 0xffff1cef05cc0000 (non-canonical:
  bits 63:48=0xFFFF but bit47=0) -> Fatal trap 9 GPF err=0 right after
  'APIC: CPU 0 has ACPI ID 0'.

THE v2 FIX (this ONE call site — the designed-object pattern):
  hook [0x9e92a634, 0x9e92a639) (5B 'call 0x9e8f33b0'):
    replay the original vm_map_find;
    THE SIZE from r15 (0x9e92a623: shl r15d,0xe; add r15d,0x4000 ->
      r15 = pages*16K + 16K, upper bits zeroed by the 32-bit ops; r15 is
      callee-saved so the replayed call preserves it);
    validate the cursor is INSIDE [BASE, CEIL] before carving (guards
      against any non-window/garbage cursor — low or high);
    carve a 0x4000-aligned, 16K-rounded-size region from the SHARED bump
    window (REAL QEMU RAM, DMAP-mapped, zero — the 0x9eccedb0 zeroer still
    runs through the DMAP alias on the real pages);
    window exhausted / cursor out of range -> fall back to the original
    vm_map_find result.
  Registers: r12 (the kstack header), r14 (the object), r15 (the size),
  rbx (pages) are callee-saved and untouched; rax/rcx/rdx/rsi/rdi/
  r8-r11 are caller-saved (the original call clobbers them anyway).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE = 0x9E402F00
S     = 0x9E92A634                       # the stack-VA alloc call site
VMMAP = 0xFFFFFFFF9E8F33B0               # vm_map_find
CONT = 0xFFFFFFFF9E92A639                # test rax, rax (the designed flow)

CURSOR = 0xFFFF8E773F1A0830
BASE   = 0xFFFF8E773F1A1000
CEIL   = 0xFFFF8E773F740000

C = f"""
    call {VMMAP:#x}
    push rbp
    push rax
    mov  r10, {CURSOR:#x}
    mov  rax, qword ptr [r10]
    test rax, rax
    jnz  have_cur
    movabs rax, {BASE:#x}
have_cur:
    add  rax, 0x3fff
    and  rax, -16384
    movabs rdx, {BASE:#x}
    cmp  rax, rdx
    jb   window_full
    movabs rdx, {CEIL:#x}
    cmp  rax, rdx
    jae  window_full
    mov  r11, rax
    mov  rdi, r15
    add  rdi, 0x3fff
    and  rdi, -16384
    add  r11, rdi
    cmp  r11, rdx
    ja   window_full
    mov  qword ptr [r10], r11
    add  rsp, 8
    pop  rbp
    jmp  {CONT:#x}
window_full:
    pop  rax
    pop  rbp
    jmp  {CONT:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C, CAVE)
print(f"cave83 @0x{CAVE:x}: {len(code):#x}B")
assert len(code) <= 0x100, "cave too big"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

off = S - KTEXT
site = bytes(img[off:off+5])
if site[:1] == b"\xe9":
    cur_target = S + 5 + int.from_bytes(site[1:5], "little", signed=True)
    if cur_target != CAVE:
        print(f"FAIL site {S:#x}: E9 -> 0x{cur_target:x} (unexpected)"); sys.exit(1)
    print(f"site {S:#x}: already hooked to cave83 (idempotent)")
    hooked = True
else:
    OLD = bytes.fromhex("e8778dfcff")    # call 0x9e8f33b0
    if site != OLD:
        print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
    hooked = False

off = CAVE - KTEXT
cur = bytes(img[off:off+len(code)])
SIG = bytes.fromhex("e8")
ours_before = cur[:1] == SIG and bytes.fromhex("5550") in cur[:8]
if not all(b == 0xCC for b in cur) and cur != code and not ours_before:
    print(f"FAIL cave {CAVE:#x} not pristine CC / ours: {cur[:16].hex()}"); sys.exit(1)

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE - (S + 5)
    off = S - KTEXT
    img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- kstack stack-VA bump-window allocator (cave83 @0x9E402F00) ---")
for i in md.disasm(code, CAVE):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP19#4: kstack stack-VA bump-window allocator (cave83 @0x9E402F00)")
