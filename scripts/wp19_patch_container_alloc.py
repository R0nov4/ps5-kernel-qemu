#!/usr/bin/env python3
"""WP19 #10 — the fork-proc container object real allocator (cave90 @0x9E403C00).

CASCADE (GDB wp19_gdb_c19, Fatal trap 12 @0xffffffff9eccef7a CR2=0x350):
  fork1, right after proc_create succeeds (cave81):
      0x9f0a17d5  rax = [rbp-0x50]              ; the parent THREAD (thread0)
      0x9f0a17dd  rdi = [rax + 0x200]           ; the parent's proc-container
      0x9f0a17e4  call 0x9e6c07f0(container, &[rbp-0x40])
  inside 0x9e6c07f0 (the container fork — a PROC-with-embedded-thread-ish
  composite, fields up to +0x564, the sub-object at +0x2e8):
      0x9e6c0804  rbx = [rdi+0x20], r12 = [rdi+0x28]   ; fine — real parent
      0x9e6c080c  rdi = [0xa11485a8]            ; the container ZONE — NULL
      0x9e6c081e  call 0x9e82b880               ; bucket_alloc(zone, 0, 2)
                                                ; -> the designed NULL
      0x9e6c0823  r15 = rax + 0x2e8             ; NULL+0x2e8 = 0x2e8
      0x9e6c0830  call 0x9e64d690(0x2e8)        ; -> 0x9eccef70's initializer
      0x9eccef7a  mov qword ptr [rdi+0x68], 0   <<< CR2 = 0x350 = 0x2e8+0x68
  (frame chain: 0x9e6c0835 <- fork1 0x9f0a17e9 <- idle_setup's WP18#9
   slot <- the SYSINIT walker <- mi_startup.)

THE FIX (the designed-object pattern for this ONE call site): hook
  [0x9e6c081e, 0x9e6c0823) (5B 'call 0x9e82b880'):
    replay the alloc; rax != 0 -> the designed path (jmp 0x9e6c0823:
                 r15 = rax+0x2e8, the full designed field init runs on
                 the REAL object);
    rax == 0  -> carve a page-aligned, zeroed 0x1000 object from the
                 SHARED bump window (covers the +0x564 fields and the
                 +0x2e8 sub-object; cursor validated inside [BASE,CEIL]);
    window exhausted -> the designed NULL return to fork1: unwind
                 0x9e6c07f0's own frame (add rsp,0x38; pop rbx..rbp;
                 ret) with rax = 0 — fork1's own NULL check at
                 0x9f0a17ed ('test rax,rax; je 0x9f0a1817') then takes
                 its designed skip.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE = 0x9E403C00
S     = 0x9E6C081E                       # the container-zone alloc call site
ZONEALLOC = 0xFFFFFFFF9E82B880
BZERO = 0xFFFFFFFF9E648FF0
CONT = 0xFFFFFFFF9E6C0823                # lea r15,[rax+0x2e8] (the designed flow)
OBJ_SIZE = 0x1000                        # covers +0x564 and the +0x2e8 sub-object

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
    xor  eax, eax
    add  rsp, 0x38
    pop  rbx
    pop  r12
    pop  r13
    pop  r14
    pop  r15
    pop  rbp
    ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C, CAVE)
print(f"cave90 @0x{CAVE:x}: {len(code):#x}B")
assert len(code) <= 0x180, "cave too big"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

off = S - KTEXT
site = bytes(img[off:off+5])
if site[:1] == b"\xe9":
    cur_target = S + 5 + int.from_bytes(site[1:5], "little", signed=True)
    if cur_target != CAVE:
        print(f"FAIL site {S:#x}: E9 -> 0x{cur_target:x} (unexpected)"); sys.exit(1)
    print(f"site {S:#x}: already hooked to cave90 (idempotent)")
    hooked = True
else:
    OLD = bytes.fromhex("e85db01600")    # call 0x9e82b880
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
print("--- fork-proc container object real allocator (cave90 @0x9E403C00) ---")
for i in md.disasm(code, CAVE):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP19#10: fork-proc container object real allocator (cave90 @0x9E403C00)")
