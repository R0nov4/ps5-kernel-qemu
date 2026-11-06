#!/usr/bin/env python3
"""WP19 #3 — the kstack-zone-object real allocator (cave82 @0x9E402E00).

CASCADE (GDB wp19_gdb_c1..c4, the trap-catch at 0x9e7de0e0): with the
WP19 thread/proc caves live, fork1 proceeds deep into the kthread
pipeline:
    fork1 -> 0x9f0a17aa -> proc_create 0x9ef80a40 (cave81: the REAL proc
    object @DMAP(0x3F2D0000)) -> proc_setup 0x9e92a540 -> the kstack
    alloc 0x9e851ac0:
        rdi = [0xa190e0c0]           ; the kstack/worker zone — ZERO
        call 0x9e82b880              -> NULL
        call 0x9e851670(NULL)        ; the WP18#23 guard no-ops it
    back in proc_setup: r12 = NULL; the stores [r14+0x468/0x470/0x478]
    run on the real proc object, then
        mtx_lock(r12 + 0x18)         <<< CR2 = 0x18 (0x9ebc46c4)
  The zone object is an 'allocation header' (lock@+0x18, list head
  {next@+0x68, prev@+0x70}, +0x50, +0x9d domain byte — all < 0xA0).

THE FIX (the same WP19 designed-object pattern, this ONE call site):
  hook [0x9e851ae7, 0x9e851aec) (5B 'call 0x9e82b880'):
    replay the original zone-alloc;
    rax != 0  -> the designed path (jmp 0x9e851aec);
    rax == 0  -> carve a page-aligned, zeroed 0x1000 object from the
                 SHARED bump window (the same cursor as cave80/81/50/56);
                 bzero it; seed the embedded lock word [+0x18] := 1 (the designed takeable state the fast path cmpxchg expects); rax = the object; jmp 0x9e851aec.
  With a real object, the WP18#23 guard passes it through and
  0x9e851670 initializes the header's list head + domain fields for real.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE = 0x9E402E00
S     = 0x9E851AE7                       # the kstack-zone alloc call site
ZONEALLOC = 0xFFFFFFFF9E82B880
BZERO = 0xFFFFFFFF9E648FF0
CONT = 0xFFFFFFFF9E851AEC                # mov edi, r12d (the designed flow)
OBJ_SIZE = 0x1000                        # one page — covers the +0xA0 fields

CURSOR = 0xFFFF8E773F1A0830
BASE   = 0xFFFF8E773F1A1000
CEIL   = 0xFFFF8E773F740000

C = f"""
    call {ZONEALLOC:#x}
    test rax, rax
    jnz  done
    push rbp
    mov  r10, {CURSOR:#x}
    mov  rax, qword ptr [r10]
    test rax, rax
    jnz  have_cur
    movabs rax, {BASE:#x}
have_cur:
    add  rax, 0xfff
    and  rax, -4096
    movabs rdx, {BASE:#x}
    cmp  rax, rdx
    jb   window_full
    movabs rdx, {CEIL:#x}
    cmp  rax, rdx
    jae  window_full
    lea  r11, [rax + {OBJ_SIZE:#x}]
    cmp  r11, rdx
    ja   window_full
    mov  qword ptr [r10], r11
    push rax
    mov  rdi, rax
    mov  esi, {OBJ_SIZE:#x}
    call {BZERO:#x}
    pop  rax
    mov  dword ptr [rax + 0x18], 1
    pop  rbp
done:
    jmp  {CONT:#x}
window_full:
    pop  rbp
    xor  eax, eax
    jmp  {CONT:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C, CAVE)
print(f"cave82 @0x{CAVE:x}: {len(code):#x}B")
assert len(code) <= 0x180, "cave too big"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

off = S - KTEXT
site = bytes(img[off:off+5])
if site[:1] == b"\xe9":
    cur_target = S + 5 + int.from_bytes(site[1:5], "little", signed=True)
    if cur_target != CAVE:
        print(f"FAIL site {S:#x}: E9 -> 0x{cur_target:x} (unexpected)"); sys.exit(1)
    print(f"site {S:#x}: already hooked to cave82 (idempotent)")
    hooked = True
else:
    OLD = bytes.fromhex("e8949dfdff")    # call 0x9e82b880
    if site != OLD:
        print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
    hooked = False

off = CAVE - KTEXT
cur = bytes(img[off:off+len(code)])
SIG = bytes.fromhex("4885c0")
ours_before = cur[:1] == b"\xe8" and SIG in cur[:12]
if not all(b == 0xCC for b in cur) and cur != code and not ours_before:
    print(f"FAIL cave {CAVE:#x} not pristine CC / ours: {cur[:16].hex()}"); sys.exit(1)

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE - (S + 5)
    off = S - KTEXT
    img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- kstack-zone-object real allocator (cave82 @0x9E402E00) ---")
for i in md.disasm(code, CAVE):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP19#3: kstack-zone-object real allocator (cave82 @0x9E402E00)")
