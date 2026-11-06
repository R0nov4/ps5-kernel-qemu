#!/usr/bin/env python3
"""WP16 #8 — region-manager insert skip for the zero manager (crash 0x9e6bb4cc CR2=0x28).

ROOT CAUSE (GDB):
  kmem_suballoc now succeeds through cave47 (the VA bump) + cave48 (the
  sub-manager constructor object) -> the post-alloc INSERT: 0x9e8f3cee
  'call 0x9e6bb380(mgr, min, max, node)' -> the insert walks the
  manager's free-space tree (0x9e6bb4c8 'mov r13,[r13+8]' /
  0x9e6bb4cc 'cmp r12,[r13+0x28]') -> the ZERO-page manager's tree is
  all NULL (no sentinel, no root) -> [NULL+0x28] -> CR2=0x28 panic.
  In the designed kernel the manager's tree is a real RB-tree with a
  header sentinel; our zero page has none.

FIX — cave49 @0x9E401180 replacing the insert entry
  [0x9e6bb380, 0x9e6bb391) (17B prologue):
    - a REAL manager ([rdi+0x1a8] != 0): replay the prologue, continue
      0x9e6bb391 (the designed insert, untouched)
    - the ZERO-page manager: return 0 (the designed 'inserted' code —
      the caller's 'test eax,eax; jne fail' takes the success path).
      The tree stays empty: nothing consults it afterwards — cave47
      answers every future region alloc from the bump window, so the
      manager's extent tree is decorative in our reconstruction.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE49 = 0x9E401180
S49, S49E = 0x9E6BB380, 0x9E6BB391          # the insert prologue (17B)

OLD49 = bytes.fromhex(
    "55"              # push rbp
    "4889e5"          # mov rbp, rsp
    "4157"            # push r15
    "4156"            # push r14
    "4155"            # push r13
    "4154"            # push r12
    "53"              # push rbx
    "4883ec18"        # sub rsp, 0x18
)

C49 = f"""
    test rdi, rdi
    jz   orig
    cmp  qword ptr [rdi + 0x1a8], 0
    jne  orig
    xor  eax, eax
    ret
orig:
    push rbp
    mov  rbp, rsp
    push r15
    push r14
    push r13
    push r12
    push rbx
    sub  rsp, 0x18
    jmp  {0xFFFFFFFF9E6BB391:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C49, CAVE49)
print(f"cave49: {len(code):#x}B @ {CAVE49:#x}  hook {S49:#x} ({len(OLD49)}B)")
assert len(code) <= 0x80, "cave49 too big"

img = bytearray(open(IMG, "rb").read())

off = S49 - KTEXT
site = bytes(img[off:off+len(OLD49)])
if site[:1] == b"\xe9":
    rel_expect = CAVE49 - (S49 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S49:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S49:#x}: already hooked to cave49 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD49:
        print(f"FAIL site {S49:#x}: {site.hex()} (expected {OLD49.hex()})"); sys.exit(1)
    hooked = False

off = CAVE49 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave {CAVE49:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

md = Cs(CS_ARCH_X86, CS_MODE_64)
insns = list(md.disasm(code, CAVE48 := CAVE49))
print("--- cave49 ---")
for i in insns:
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE49 - (S49 + 5)
    off = S49 - KTEXT
    img[off:off+len(OLD49)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD49) - 5)

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP16#8: region-mgr insert skip (cave49)")
