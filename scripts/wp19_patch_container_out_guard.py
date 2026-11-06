#!/usr/bin/env python3
"""WP19 #14 — fork1's container-out NULL guard (cave94 @0x9E404400).

CASCADE (GDB wp19_gdb_c48, the 119x fault loop at 0xffffffff9e9f9896,
  CR2=0x80): with caves 80..93 live, fork1's post-container step:
      0x9f0a17e4  call 0x9e6c07f0(parent_container, &[rbp-0x40])
                  ; the container fork (cave90 supplies the real object)
      0x9f0a17e9  [rbp-0x50] = rax          ; the new container — REAL
      0x9f0a17f2  rdi = [rbp-0x40]          ; the fn's OUT param — never
                                            ; written on this boot (the
                                            ; designed out-writer lives
                                            ; in a branch state our march
                                            ; never produces) -> NULL
      0x9f0a17f6  call 0x9e6711c0(NULL)
      0x9e9f9896  mov rcx, [rdi + 0x80]     <<< CR2 = 0x80 READ, looping
  (frame chain: <- fork1 0x9f0a17fb <- idle_setup's WP18#9 slot <- the
   SYSINIT walker <- mi_startup.)

THE FIX (the designed NULL-tolerant skip, this ONE call site): hook
  [0x9f0a17f6, 0x9f0a17fb) (5B 'call 0x9e6711c0'):
    rdi != 0  -> the original call, then the designed continuation;
    rdi == 0  -> skip the call: eax = 0; jmp 0x9f0a17fb — the designed
                 zero-result flows into the existing 'test eax,eax'
                 fall-through (the same path the container-NULL skip
                 at 0x9f0a17ed/0x9f0a1817 already takes).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE = 0x9E404400
S     = 0x9F0A17F6                       # fork1's container-out call site
FN    = 0xFFFFFFFF9E6711C0               # the original call
CONT = 0xFFFFFFFF9F0A17FB                # test eax, eax (the designed flow)

OLD = bytes.fromhex("e8c5f95cff")        # call 0x9e6711c0

C = f"""
    test rdi, rdi
    jz   skip_call
    movabs rax, 0xffff8e7700000000
    cmp  rdi, rax
    jb   kimg_chk
    movabs rax, 0xffff8e7780000000
    cmp  rdi, rax
    jb   do_call
kimg_chk:
    movabs rax, 0xffffffff9e3f0000
    cmp  rdi, rax
    jb   skip_call
    movabs rax, 0xffffffffa2220000
    cmp  rdi, rax
    jb   do_call
    jmp  skip_call
do_call:
    call {FN:#x}
    jmp  {CONT:#x}
skip_call:
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
print(f"cave94 @0x{CAVE:x}: {len(code):#x}B")
assert len(code) <= 0x80, "cave too big"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

off = S - KTEXT
site = bytes(img[off:off+5])
if site[:1] == b"\xe9":
    cur_target = S + 5 + int.from_bytes(site[1:5], "little", signed=True)
    if cur_target != CAVE:
        print(f"FAIL site {S:#x}: E9 -> 0x{cur_target:x} (unexpected)"); sys.exit(1)
    print(f"site {S:#x}: already hooked to cave94 (idempotent)")
    hooked = True
else:
    if site != OLD:
        print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
    hooked = False

off = CAVE - KTEXT

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE - (S + 5)
    off = S - KTEXT
    img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- fork1 container-out NULL guard (cave94 @0x9E404400) ---")
for i in md.disasm(code, CAVE):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP19#14: fork1 container-out NULL guard (cave94 @0x9E404400)")
