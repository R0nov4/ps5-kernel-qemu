#!/usr/bin/env python3
"""WP16 #17 — lock-domain stats helper NULL guard (crash 0x9e81dd69 CR2=0x20 R).

ROOT CAUSE (GDB):
  The kmem arena's alloc path locks the arena's own mutex -> the mtx
  slow path (0x9e8b70xx) -> the lock-class/domain lookup 0x9e81d680
  returns NULL (the lock-domain arrays never initialized on this boot)
  -> 'call 0x9e81dd40(NULL, 0)' (the per-domain lock-stats helper) ->
  'mov rcx, [rbx+rax+0x20]' with rbx = rax = 0 -> CR2=0x20.
  The helper is pure bookkeeping (the lock statistics table) — skipping
  it for a NULL table is harmless.

FIX — cave59 @0x9E401680 replacing [0x9e81dd40, 0x9e81dd4a) (10B
  prologue: push rbp; mov rbp,rsp; push r15; push r14; push rbx;
  push rax):
    - rdi == 0: plain ret (no stats recorded — the lock still works,
      only its accounting is skipped)
    - rdi != 0: replay the prologue, continue 0x9e81dd4a.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE59 = 0x9E401680
S59, S59E = 0x9E81DD40, 0x9E81DD4A          # the prologue (10B)

OLD59 = bytes.fromhex(
    "55"              # push rbp
    "4889e5"          # mov rbp, rsp
    "4157"            # push r15
    "4156"            # push r14
    "53"              # push rbx
    "50"              # push rax
)

C59 = f"""
    test rdi, rdi
    jz   skip
    push rbp
    mov  rbp, rsp
    push r15
    push r14
    push rbx
    push rax
    jmp  {0xFFFFFFFF9E81DD4A:#x}
skip:
    ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C59, CAVE59)
print(f"cave59: {len(code):#x}B @ {CAVE59:#x}  hook {S59:#x} ({len(OLD59)}B)")
assert len(code) <= 0x80, "cave59 too big"

img = bytearray(open(IMG, "rb").read())

off = S59 - KTEXT
site = bytes(img[off:off+len(OLD59)])
if site[:1] == b"\xe9":
    rel_expect = CAVE59 - (S59 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S59:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S59:#x}: already hooked to cave59 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD59:
        print(f"FAIL site {S59:#x}: {site.hex()} (expected {OLD59.hex()})"); sys.exit(1)
    hooked = False

off = CAVE59 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave {CAVE59:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

md = Cs(CS_ARCH_X86, CS_MODE_64)
insns = list(md.disasm(code, CAVE59))

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE59 - (S59 + 5)
    off = S59 - KTEXT
    img[off:off+len(OLD59)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD59) - 5)

print("--- cave59 ---")
for i in insns:
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP16#17: lock-stats helper NULL guard (cave59)")
