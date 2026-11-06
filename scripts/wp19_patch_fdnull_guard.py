#!/usr/bin/env python3
"""WP19 #6 — fork1's NULL-parent filedesc guard (cave85 @0x9E403200).

CONTEXT (GDB wp19_gdb_c7): fork1's flag-4 branch calls the fd-copy fn:
      0x9f0a2042  rdi = [r15 + 0x48]        ; the PARENT proc's p_fd
      0x9f0a2046  test al, 4                ; the fresh/copy fd flag
      0x9f0a2048  jne 0x9f0a20b0
      0x9f0a20b0  call 0x9eb1d0d0(rdi)      ; fd-copy(parent fd)
  For the kthread/kproc forks the parent is the proc0-style kernel proc
  whose p_fd is NULL — and 0x9eb1d0d0 derefs the parent unguarded:
      0x9eb1d0f8  cmp dword [rbx+0x28], 0   ; the parent's fd count  <<<
      0x9eb1d24c  movzx eax, word [rbx+0x30]; the parent's flags      <<<
      0x9eb1d261  call 0x9f03c300(parent+0x40)                          <<<
  (crash frame chain: 0x9eb1d0ee <- fork1 0x9f0a20b5 <- 0x9f0a1914 <-
   idle_setup's WP18#8 slot <- the SYSINIT walker <- mi_startup).

THE FIX (the DESIGNED fresh-fd semantics for the NULL-parent case, this
  ONE call site): hook [0x9f0a20b0, 0x9f0a20b5) (5B 'call 0x9eb1d0d0'):
    rdi != 0  -> the original fd-copy (the cave calls it, then returns
                 to 0x9f0a20b5 — untouched designed path);
    rdi == 0  -> the RFCFDG-with-no-parent designed flow:
                 finew(NULL, 1) — which itself HANDLES the NULL parent
                 (0x9eb1ce53 'test r14,r14; je' skips the parent-init) —
                 then the js-skip tail value [fd+0x2c] = 0 and NO parent
                 references at all; rax (the fresh fd or NULL) flows to
                 0x9f0a20b5 exactly as the original call's result would.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE = 0x9E403200
S     = 0x9F0A20B0                       # fork1's fd-copy call site
FDCOPY = 0xFFFFFFFF9EB1D0D0              # the original fd-copy fn
FINEW = 0xFFFFFFFF9EB1CDE0               # finew (NULL-parent safe)
CONT = 0xFFFFFFFF9F0A20B5                # mov [rbp-0x40], rax

OLD = bytes.fromhex("e81bb0a7ff")        # call 0x9eb1d0d0

C = f"""
    test rdi, rdi
    jnz  real_call
    mov  esi, 1
    call {FINEW:#x}
    test rax, rax
    jz   null_out
    mov  dword ptr [rax + 0x2c], 0
null_out:
    jmp  {CONT:#x}
real_call:
    call {FDCOPY:#x}
    jmp  {CONT:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C, CAVE)
print(f"cave85 @0x{CAVE:x}: {len(code):#x}B")
assert len(code) <= 0x100, "cave too big"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

off = S - KTEXT
site = bytes(img[off:off+5])
if site[:1] == b"\xe9":
    cur_target = S + 5 + int.from_bytes(site[1:5], "little", signed=True)
    if cur_target != CAVE:
        print(f"FAIL site {S:#x}: E9 -> 0x{cur_target:x} (unexpected)"); sys.exit(1)
    print(f"site {S:#x}: already hooked to cave85 (idempotent)")
    hooked = True
else:
    if site != OLD:
        print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
    hooked = False

off = CAVE - KTEXT
cur = bytes(img[off:off+len(code)])
SIG = bytes.fromhex("4885ff")   # 'test rdi, rdi' — our own cave signature
ours_before = cur[:3] == SIG
if not all(b == 0xCC for b in cur) and cur != code and not ours_before:
    print(f"FAIL cave {CAVE:#x} not pristine CC / ours: {cur[:16].hex()}"); sys.exit(1)

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE - (S + 5)
    off = S - KTEXT
    img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- fork1 NULL-parent filedesc guard (cave85 @0x9E403200) ---")
for i in md.disasm(code, CAVE):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP19#6: fork1 NULL-parent filedesc guard (cave85 @0x9E403200)")
