#!/usr/bin/env python3
"""WP19 #9 — the thread-cpuset object real allocator (cave89 @0x9E403A00).

CASCADE (GDB wp19_gdb_c14, Fatal trap 12 @0xffffffff9ec2cf76 CR2=0x0):
  with fork1 now completing (caves 80..88: thread, proc, kstack zone,
  kstack VA, filedesc, the NULL-parent fd guard, the cpuset ROOT SET,
  the child sigacts), the kproc_create POST-FORK step runs — assigning
  the fresh kthread its cpuset (fn 0x9ec2ca40, called from the kproc
  machinery 0x9ed157d2 <- idle_setup's WP18#8 slot <- the SYSINIT walker):
      0x9ec2ca50  rdi = [0xa1e71ea8]        ; the cpuset ZONE — NULL
      0x9ec2ca64  call 0x9e82b880           ; bucket_alloc(zone, 0, 2)
                                            ; -> the designed NULL
      0x9ec2ca6b  rbx = rax                 ; the new set object = NULL
      ... (the curthread's root set is read — REAL since cave86/87:
            rsi = [thread0+0x60] = the ROOT SET; the mask checks pass)
      0x9ec2cb0c  rdi = rbx                 ; NULL
      0x9ec2cb17  call 0x9ec2cf60           ; cpuset_init(NULL, root, ...)
      0x9ec2cf76  mov qword ptr [rdi], rax  <<< CR2 = 0x0 WRITE
  (the init writes the mask/-1, [+0x40]=0, [+0x8]=1, [+0xc]=0 — the
   zone's 0x48-byte object.)

THE FIX (the designed-object pattern for this ONE call site — the
  general zone_create path untouched): hook [0x9ec2ca64, 0x9ec2ca69)
  (5B 'call 0x9e82b880'):
    replay the alloc; rax != 0 -> the designed path (jmp 0x9ec2ca69:
                 rbx = rax; the designed cpuset_init runs on the REAL
                 object);
    rax == 0  -> carve a page-aligned, zeroed object from the SHARED
                 bump window (cursor validated inside [BASE, CEIL]);
    window exhausted -> the designed error exit: jmp 0x9ec2cb28
                 ('mov r12d, 3; jmp the epilogue' — the fn's own
                 error-return path; the frame is intact at the hook
                 point).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE = 0x9E403A00
S     = 0x9EC2CA64                       # the cpuset-zone alloc call site
ZONEALLOC = 0xFFFFFFFF9E82B880
BZERO = 0xFFFFFFFF9E648FF0
CONT = 0xFFFFFFFF9EC2CA69                # mov edi, ebx (the designed flow)
ERRPATH = 0xFFFFFFFF9EC2CB28             # mov r12d, 3; jmp the epilogue
OBJ_SIZE = 0x1000                        # page-carve covering the 0x48 zone object

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
    pop  rbp
done:
    jmp  {CONT:#x}
window_full:
    pop  rbp
    jmp  {ERRPATH:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C, CAVE)
print(f"cave89 @0x{CAVE:x}: {len(code):#x}B")
assert len(code) <= 0x180, "cave too big"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

off = S - KTEXT
site = bytes(img[off:off+5])
if site[:1] == b"\xe9":
    cur_target = S + 5 + int.from_bytes(site[1:5], "little", signed=True)
    if cur_target != CAVE:
        print(f"FAIL site {S:#x}: E9 -> 0x{cur_target:x} (unexpected)"); sys.exit(1)
    print(f"site {S:#x}: already hooked to cave89 (idempotent)")
    hooked = True
else:
    OLD = bytes.fromhex("e817eebfff")    # call 0x9e82b880
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
print("--- thread-cpuset object real allocator (cave89 @0x9E403A00) ---")
for i in md.disasm(code, CAVE):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP19#9: thread-cpuset object real allocator (cave89 @0x9E403A00)")
