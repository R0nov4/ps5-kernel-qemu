#!/usr/bin/env python3
"""WP19 #5 — finew's FILEDESC-object real allocator (cave84 @0x9E403000).

CASCADE (GDB wp19_gdb_c7 trap-catch, Fatal trap 12 @0xffffffff9eb1d0ee
  CR2=0x2c WRITE): with the WP19 thread/proc/kstack caves live, fork1's
  deep pipeline reaches the filedesc stage:
      fork1 0x9f0a2048 (flag-4 branch) -> 0x9eb1d0d0(the fd-copy, rdi =
      [parentproc+0x48] = the parent's p_fd = NULL for the proc0-style
      kthread parent)
    -> 0x9eb1d0e9  call 0x9eb1cde0 (finew: 'filedesc structure')
    -> 0x9eb1cdee  rdi = [0xa1d71eb0]      ; the filedesc zone — ZERO
    -> 0x9eb1cdff  call 0x9e82b880          ; zone-alloc -> NULL
                   (the WP18#4 slot's designed NULL)
    -> finew returns NULL
    -> 0x9eb1d0ee  mov dword [rax+0x2c], -1 <<< CR2 = 0x2c
  (this exact flow was FORESEEN in the WP18#4 docstring: '0x9eb1d0ee
   writes [rax+0x2c] (a different flow — not in this march; will be
   guarded locally if it ever appears)' — it has now appeared.)

THE FIX (the designed-object pattern for this ONE call site — the general
  zone_create path untouched): re-point the EXISTING WP18#4 E9 at
  0x9eb1cdff from slot 0x9E401E00 to cave84:
    replay the original zone-alloc;
    rax != 0  -> the designed path (jmp 0x9eb1ce04: the full 'filedesc
                 structure' initialization runs on a REAL object — the
                 embedded fields +0x34/+0x38/+0x30/+0x20(=+0x460)/+0x28/
                 +0/+0x98 and the type-name sub-init 0x9f03b290);
    rax == 0  -> carve a page-aligned, zeroed 0x1000 object from the
                 SHARED bump window (the same cursor [DMAP(0x3F1A0830)]
                 as cave80..83/50/56 — interlocked by construction; the
                 cursor is validated inside [BASE, CEIL] first);
    window exhausted / cursor out of range -> the WP18#4 designed NULL
                 protocol: xor eax,eax; jmp finew's own epilogue-tail
                 0x9eb1cf2e (pop rbx; pop r12; pop r14; pop r15; pop
                 rbp; ret).
  The object size: the designed init writes up to [+0x460]+8 and keeps an
  inline 20-entry table at +0x98 — a 0x1000 page covers it (0x468).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE = 0x9E403000
S     = 0x9EB1CDFF                       # finew's zone-alloc call site
OLD_SLOT = 0x9E401E00                    # the WP18#4 slot (current E9 target)
ZONEALLOC = 0xFFFFFFFF9E82B880           # the original zone-alloc wrapper
BZERO = 0xFFFFFFFF9E648FF0               # the kernel's bzero(rdi, rsi)
CONT = 0xFFFFFFFF9EB1CE04                # the designed 'filedesc structure' init
EXIT = 0xFFFFFFFF9EB1CF2E                # finew's NULL epilogue-tail
OBJ_SIZE = 0x1000                        # one page — covers the +0x468 fields

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
    jmp  {EXIT:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C, CAVE)
print(f"cave84 @0x{CAVE:x}: {len(code):#x}B")
assert len(code) <= 0x180, "cave too big"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

off = S - KTEXT
site = bytes(img[off:off+5])
if site[:1] == b"\xe9":
    cur_target = S + 5 + int.from_bytes(site[1:5], "little", signed=True)
    if cur_target == CAVE:
        print(f"site {S:#x}: already points at cave84 (idempotent)")
    elif cur_target == OLD_SLOT:
        print(f"site {S:#x}: WP18#4 E9 -> 0x{OLD_SLOT:x} confirmed, re-pointing to cave84")
    else:
        print(f"FAIL site {S:#x}: E9 -> 0x{cur_target:x} (unexpected)"); sys.exit(1)
else:
    print(f"FAIL site {S:#x}: {site.hex()} is not an E9 hook (run WP18#4 first)"); sys.exit(1)

off = CAVE - KTEXT
cur = bytes(img[off:off+len(code)])
SIG = bytes.fromhex("4885c0")   # 'test rax, rax' — our own cave signature
ours_before = cur[:1] == b"\xe8" and SIG in cur[:12]
if not all(b == 0xCC for b in cur) and cur != code and not ours_before:
    print(f"FAIL cave {CAVE:#x} not pristine CC / ours: {cur[:16].hex()}"); sys.exit(1)

img[off:off+len(code)] = code

rel = CAVE - (S + 5)
off = S - KTEXT
img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- finew FILEDESC-object real allocator (cave84 @0x9E403000) ---")
for i in md.disasm(code, CAVE):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP19#5: finew FILEDESC-object real allocator (cave84 @0x9E403000)")
