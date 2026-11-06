#!/usr/bin/env python3
"""WP16 #12 — OID tree walk NULL-terminator guard (crash 0x9eef4158 CR2=0x18 R).

ROOT CAUSE (GDB):
  The sysctl-registration stage ('can't re-use a leaf (zone_warnings)!'
  ... hundreds of leaves, 'Preloaded elf kernel "kernel" ...') calls the
  OID-tree search helper 0x9eef4130 (the duplicate check):
    0x9eef4150  mov rsi, [rsi]           ; next sibling
    0x9eef4153  cmp rsi, rdi             ; the OID node being checked
    0x9eef4156  je 0x9eef4163            ; duplicate -> 'xor eax,eax; ret'
    0x9eef4158  mov rax, [rsi+0x18]      ; the subtree link
    0x9eef415c  test rax, rax
    0x9eef415f  je 0x9eef4150            ; no subtree -> next sibling
    (fallthrough: found -> ret)
  The walk's list terminator is NULL (the tree/list nodes live in the
  STATIC registration data whose links were wiped to 0) -> rsi = 0 ->
  'mov rax, [0+0x18]' -> CR2=0x18 panic.
  The designed tree terminates with valid nodes; ours terminates with
  NULL.

FIX — cave52 @0x9E401300 replacing [0x9eef4158, 0x9eef4160) (7B:
  'mov rax,[rsi+0x18]; test rax,rax'):
    - rsi == 0 (the exhausted walk): jump to the designed zero-answer
      exit 0x9eef4163 ('xor eax,eax; pop rbp; ret') — the same answer
      the duplicate path returns; the caller prints 'can't re-use a
      leaf' and continues the registration exactly like every other
      leaf of this stage (the normal output of this boot).
    - rsi != 0: replay 'mov rax,[rsi+0x18]' and jump back to 0x9eef415c
      (the original test+je run untouched).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE52 = 0x9E401300
S52, S52E = 0x9EEF4158, 0x9EEF4160          # mov rax,[rsi+0x18]; test rax,rax (7B)

OLD52 = bytes.fromhex("488b46184885c0")

C52 = f"""
    test rsi, rsi
    jz   not_found
    mov  rax, qword ptr [rsi + 0x18]
    jmp  {0xFFFFFFFF9EEF415C:#x}
not_found:
    jmp  {0xFFFFFFFF9EEF4163:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C52, CAVE52)
print(f"cave52: {len(code):#x}B @ {CAVE52:#x}  hook {S52:#x} ({len(OLD52)}B)")
assert len(code) <= 0x80, "cave52 too big"

img = bytearray(open(IMG, "rb").read())

off = S52 - KTEXT
site = bytes(img[off:off+len(OLD52)])
if site[:1] == b"\xe9":
    rel_expect = CAVE52 - (S52 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S52:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S52:#x}: already hooked to cave52 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD52:
        print(f"FAIL site {S52:#x}: {site.hex()} (expected {OLD52.hex()})"); sys.exit(1)
    hooked = False

off = CAVE52 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave {CAVE52:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

md = Cs(CS_ARCH_X86, CS_MODE_64)
insns = list(md.disasm(code, CAVE52))

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE52 - (S52 + 5)
    off = S52 - KTEXT
    img[off:off+len(OLD52)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD52) - 5)

print("--- cave52 ---")
for i in insns:
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP16#12: OID tree walk NULL guard (cave52)")
