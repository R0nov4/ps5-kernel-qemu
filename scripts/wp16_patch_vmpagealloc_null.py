#!/usr/bin/env python3
"""WP16 #4 — vm_page_alloc second-chance NULL guard (crash 0x9ef7a475 CR2=0x50).

ROOT CAUSE (GDB-stepped):
  vm_page_startup's fill loop (0x9e8f3ee0, one call per 4KB page, ~524288
  iterations for the 2GB QEMU RAM) -> vm_page_alloc (0x9ef7a1a0) -> the
  W1-bump cave (hook @0x9EA05730) exhausted its 896KB region (bump =
  0x3f0f0010, 3823 objects = 14.9MB tracked) -> the second-chance call at
  0x9ef7a43c returns NULL -> 'mov r13, rax' (0x9ef7a441) -> the join at
  0x9ef7a45d does NOT re-test r13 (Sony's code assumes the second-chance
  path always yields a page) -> 'mov [r13+0x50], rax' at 0x9ef7a475
  writes NULL+0x50 -> panic.
  NOTE: the FIRST call site (0x9ef7a41c) DOES test NULL ('test rax,rax;
  jne 0x9ef7a441' at 0x9ef7a421) — only the second-chance join lacks it.

FIX (the designed NULL return):
  cave45 @0x9E400F80 replacing the join head [0x9ef7a45d, 0x9ef7a462)
  ('mov eax, 1', 5B — the join of the second-chance path 0x9ef7a44b, the
  first-allocator success 0x9ef7a347 and the 0x9e944f70 success 0x9ef7a3e8):
    - r13 != 0 -> replay 'mov eax,1', continue 0x9ef7a462 (designed)
    - r13 == 0 (NULL m) -> return NULL via the function's own epilogue:
        the 0xa2170498 page-queue lock state decides the exit (GDB: word
        == 0 = never-acquired on this path):
          word == 0 (never-init) or == 4 (free) -> direct jump to the
              epilogue 0x9ef7a716 ('mov rax, r13' = NULL, pops, ret)
          otherwise (held) -> the designed unlock+NULL exit 0x9ef7a3ea
              ('xor r13d,r13d; unlock(0xa2170498); jmp 0x9ef7a716')
      The caller (0x9e8f3eee 'test rax,rax; je 0x9e8f3ef3') has the
      designed NULL path (the 0x9ebc4eb0 call + the [rbp-0x3c]&1 check)
      -> the loop handles the shortage gracefully.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE45 = 0x9E400F80
S45, S45E = 0x9EF7A45D, 0x9EF7A462          # 'mov eax, 1' (5B) — the join head
LOCK_WORD = 0xFFFFFFFFA21704B0              # 0xa2170498 + 0x18 (the page-queue lock word)

OLD45 = bytes.fromhex("b801000000")         # mov eax, 1

C45 = f"""
    test r13, r13
    jnz  ok
    movabs rcx, {LOCK_WORD:#x}
    mov  rcx, qword ptr [rcx]
    cmp  rcx, 4
    je   direct
    test rcx, rcx
    jz   direct
    jmp  {0xFFFFFFFF9EF7A3EA:#x}
direct:
    jmp  {0xFFFFFFFF9EF7A716:#x}
ok:
    mov  eax, 1
    jmp  {0xFFFFFFFF9EF7A462:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C45, CAVE45)
print(f"cave45: {len(code):#x}B @ {CAVE45:#x}  hook {S45:#x} ({len(OLD45)}B)")
assert len(code) <= 0x80, "cave45 too big"

img = bytearray(open(IMG, "rb").read())

off = S45 - KTEXT
site = bytes(img[off:off+len(OLD45)])
if site[:1] == b"\xe9":
    rel_expect = CAVE45 - (S45 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S45:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S45:#x}: already hooked to cave45 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD45:
        print(f"FAIL site {S45:#x}: {site.hex()} (expected {OLD45.hex()})"); sys.exit(1)
    hooked = False

off = CAVE45 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave {CAVE45:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

md = Cs(CS_ARCH_X86, CS_MODE_64)
insns = list(md.disasm(code, CAVE45))
# encoding sanity: the movabs rcx, LOCK_WORD + absolute load pattern
blob = code.hex()
if "48b9b00417a2ffffffff" not in blob or "488b09" not in blob:
    for i in insns:
        print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
    print("FAIL: lock-word load pattern not found"); sys.exit(1)

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE45 - (S45 + 5)
    off = S45 - KTEXT
    img[off:off+len(OLD45)] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

print("--- cave45 ---")
for i in insns:
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP16#4: vm_page_alloc NULL guard (cave45)")
