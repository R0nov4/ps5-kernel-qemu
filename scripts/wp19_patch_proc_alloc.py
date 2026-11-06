#!/usr/bin/env python3
"""WP19 #2 — proc_create's PROC-object real allocator (cave81 @0x9E402C00).

CONTEXT (the WP19 root-cause chain): fork1's kthread path takes
  0x9f0a17aa when the fresh THREAD object's [+0x10] (td_proc) is NULL:
      0x9f0a17ad  call 0x9ef80a40(flags)        <- proc_create
  0x9ef80a40:
      0x9ef80a4a  call 0x9ef808a0
      0x9ef80a4f  rdi = [0xa2171de8]            ; the PROC zone — ZERO on this boot
      0x9ef80a5d  call 0x9e82b880               ; zone-alloc -> NULL
      0x9ef80a62  rdi = rax; rbx = rax          ; the NULL object
      0x9ef80a6b  call 0x9e92a540(rdi, flags)   ; proc_setup walks the NULL
  THE ZONE: created at 0x9ef80237 with size 0x688 (the size probe
  0x9eaa7ae0 returns 0x688) — this is the 0x688 PROC zone.

THE FIX (the user's WP19 mission #2 — the designed-object path for this
  ONE call site; the general zone_create path untouched):
  hook [0x9ef80a5d, 0x9ef80a62) (5B 'call 0x9e82b880', currently E9 ->
  the WP18#24 slot 0x9E402A00):
    replay the original zone-alloc;
    rax != 0  -> the designed path (jmp 0x9ef80a62: proc_setup runs on a
                 REAL object);
    rax == 0  -> carve a page-aligned, zeroed 0x688 PROC object from the
                 SHARED bump window (the same cursor [DMAP(0x3F1A0830)]
                 as cave80/50/56 — interlocked by construction);
    window exhausted -> the WP18#24 designed NULL-skip:
                 xor ebx,ebx; jmp 0x9ef80aa0 (returns NULL, 'no proc').
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE = 0x9E402C00
S     = 0x9EF80A5D                       # the proc_create alloc call site
OLD_SLOT = 0x9E402A00                    # the WP18#24 slot (current E9 target)
ZONEALLOC = 0xFFFFFFFF9E82B880
BZERO = 0xFFFFFFFF9E648FF0
CONT = 0xFFFFFFFF9EF80A62                # mov rdi,rax — the designed flow
EXIT = 0xFFFFFFFF9EF80AA0                # mov rax,rbx; pop rbx; pop r14; pop rbp; ret
PROC_SIZE = 0x688                        # the PROC zone object size (0x9ef80237)

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
    lea  r11, [rax + {PROC_SIZE:#x}]
    cmp  r11, rdx
    ja   window_full
    mov  qword ptr [r10], r11
    push rax
    mov  rdi, rax
    mov  esi, {PROC_SIZE:#x}
    call {BZERO:#x}
    pop  rax
    pop  rbp
done:
    jmp  {CONT:#x}
window_full:
    pop  rbp
    xor  ebx, ebx
    jmp  {EXIT:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C, CAVE)
print(f"cave81 @0x{CAVE:x}: {len(code):#x}B")
assert len(code) <= 0x180, "cave too big"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

off = S - KTEXT
site = bytes(img[off:off+5])
if site[:1] == b"\xe9":
    cur_target = S + 5 + int.from_bytes(site[1:5], "little", signed=True)
    if cur_target == CAVE:
        print(f"site {S:#x}: already points at cave81 (idempotent)")
    elif cur_target == OLD_SLOT:
        print(f"site {S:#x}: WP18#24 E9 -> 0x{OLD_SLOT:x} confirmed, re-pointing to cave81")
    else:
        print(f"FAIL site {S:#x}: E9 -> 0x{cur_target:x} (unexpected)"); sys.exit(1)
else:
    print(f"FAIL site {S:#x}: {site.hex()} is not an E9 hook (run WP18#24 first)"); sys.exit(1)

off = CAVE - KTEXT
cur = bytes(img[off:off+len(code)])
SIG = bytes.fromhex("4885c0")   # 'test rax, rax' — our own cave signature (after the replay call)
ours_before = cur[:1] == b"\xe8" and SIG in cur[:12]
if not all(b == 0xCC for b in cur) and cur != code and not ours_before:
    print(f"FAIL cave {CAVE:#x} not pristine CC / ours: {cur[:16].hex()}"); sys.exit(1)

img[off:off+len(code)] = code

rel = CAVE - (S + 5)
off = S - KTEXT
img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- proc_create PROC-object real allocator (cave81 @0x9E402C00) ---")
for i in md.disasm(code, CAVE):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP19#2: proc_create PROC-object real allocator (cave81 @0x9E402C00)")
