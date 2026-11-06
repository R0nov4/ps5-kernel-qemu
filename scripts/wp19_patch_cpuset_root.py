#!/usr/bin/env python3
"""WP19 #7 — the cpuset bootstrap's real objects (cave86 @0x9E403400 +
             cave87 @0x9E403600): the ROOT SET finally exists.

CASCADE (GDB wp19_gdb_c8, Fatal trap 12 @0xffffffff9ec2c374 CR2=0x8):
  fork1's deep pipeline reaches sched_fork (0x9eaa5430):
      0x9eaa5475  rdi = [thread0 + 0x60]     ; the parent's cpuset — thread0
                                             ; IS the static bss thread, so
                                             ; +0x60 = 0xa19788c0 = the very
                                             ; 'root cpuset object global'
                                             ; the WP18#3 docstring named
      0x9eaa5478  call 0x9ec2c370            ; refcount_hold: 'lock add
                                             ; [rdi+8],1' -> CR2 = 0x8
  ROOT CAUSE: thread0.td_cpuset ([0xa19788c0]) is NULL because the cpuset
  bootstrap SYSINIT (fn 0x9ec2d040) never built the root set — its TWO
  bucket_alloc calls answer the designed NULL (zone_create returned NULL
  in early boot; WP18#2 made the first crash-site a NULL-skip instead):
      #1  0x9ec2d097  call 0x9e82b880   ; the mask/domain object ('cpuset'
                                         ; zone, size 0x48) — mask=-1, the
                                         ; TAILQ list head, the [0xa1e71ec8/
                                         ; 0xa1e71eb8] globals
      #2  0x9ec2d102  call 0x9e82b880   ; the ROOT SET object — init'd by
                                         ; 0x9ec2cf60(obj2, obj1, 1), stored
                                         ; at [0xa1e71ec0], returned to the
                                         ; SYSINIT caller which stores it at
                                         ; [0xa19788c0] = thread0.td_cpuset

THE FIX (the designed-object pattern for these TWO call sites — the
  general zone_create path untouched):
  cave86 hooks [0x9ec2d097, 0x9ec2d09c) (5B 'call 0x9e82b880'):
    replay the alloc; rax != 0 -> the designed path; rax == 0 -> carve a
    page-aligned, zeroed object from the SHARED bump window (cursor
    validated inside [BASE, CEIL]); BOTH paths jmp 0x9ec2d09c — the
    EXISTING WP18#2 slot: a real rax gets its designed 'mov [rax],-1'
    mask + the init block; a NULL rax keeps the WP18 designed NULL-skip.
  cave87 hooks [0x9ec2d102, 0x9ec2d107) (5B 'call 0x9e82b880'):
    replay; rax != 0 -> jmp 0x9ec2d107 (the designed root-set init:
    0x9ec2cf60(obj2, obj1, 1), [0xa1e71ec0] = rbx, the epilogue returns
    rbx -> [0xa19788c0] = thread0.td_cpuset = the REAL root);
    rax == 0 -> carve the same way;
    window exhausted -> xor ebx,ebx; jmp the fn's own epilogue 0x9ec2d158
    ('mov rax,rbx') — the designed NULL return (the WP18 behavior).
  With the root set real: sched_fork refs it for every kthread child,
  the WP18#3 guard's helper takes its designed refcount path, and every
  td_cpuset reader downstream sees a real object.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

ZONEALLOC = 0xFFFFFFFF9E82B880
BZERO = 0xFFFFFFFF9E648FF0
CURSOR = 0xFFFF8E773F1A0830
BASE   = 0xFFFF8E773F1A1000
CEIL   = 0xFFFF8E773F740000
OBJ_SIZE = 0x1000                    # page-carve covering the 0x48 zone object

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

def carve_body(cont, window_tail):
    return f"""
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
    jmp  {cont:#x}
window_full:
    pop  rbp
    xor  eax, eax
{window_tail}
"""

# cave86: NULL -> the WP18#2 slot's designed NULL-skip at 0x9ec2d09c
C86 = carve_body(0xFFFFFFFF9EC2D09C, f"jmp  {0xFFFFFFFF9EC2D09C:#x}")
# cave87: NULL -> the fn's own epilogue with rbx = 0 (the designed NULL return)
C87 = carve_body(0xFFFFFFFF9EC2D107, f"xor  ebx, ebx\n    jmp  {0xFFFFFFFF9EC2D158:#x}")

SITES = [
    ("cave86 (mask/domain object)", 0x9E403400, 0x9EC2D097,
     bytes.fromhex("e8e4e7bfff"), C86),
    ("cave87 (the ROOT SET object)", 0x9E403600, 0x9EC2D102,
     bytes.fromhex("e879e7bfff"), C87),
]

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

for name, cave, site, OLD, code_src in SITES:
    code = asm(code_src, cave)
    print(f"{name} @0x{cave:x}: {len(code):#x}B")
    assert len(code) <= 0x180, "cave too big"

    off = site - KTEXT
    cur5 = bytes(img[off:off+5])
    if cur5[:1] == b"\xe9":
        tgt = site + 5 + int.from_bytes(cur5[1:5], "little", signed=True)
        if tgt != cave:
            print(f"FAIL site 0x{site:x}: E9 -> 0x{tgt:x} (unexpected)"); sys.exit(1)
        print(f"  site 0x{site:x}: already hooked to 0x{cave:x} (idempotent)")
        hooked = True
    else:
        if cur5 != OLD:
            print(f"FAIL site 0x{site:x}: {cur5.hex()} != {OLD.hex()}"); sys.exit(1)
        hooked = False

    off = cave - KTEXT
    cur = bytes(img[off:off+len(code)])
    SIG = bytes.fromhex("4885c0")
    ours_before = cur[:1] == b"\xe8" and SIG in cur[:12]
    if not all(b == 0xCC for b in cur) and cur != code and not ours_before:
        print(f"FAIL cave 0x{cave:x} not pristine CC / ours: {cur[:16].hex()}"); sys.exit(1)

    img[off:off+len(code)] = code
    if not hooked:
        rel = cave - (site + 5)
        off = site - KTEXT
        img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

    print(f"  --- {name} ---")
    for i in md.disasm(code, cave):
        print(f"    {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP19#7: cpuset bootstrap real objects — the ROOT SET exists (cave86+cave87)")
