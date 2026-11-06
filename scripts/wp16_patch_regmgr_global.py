#!/usr/bin/env python3
"""WP16 #16 — region-manager global redirect to the zero-page manager
         (crash 0x9e81dd69 CR2=0x20 R — lock through the garbage map).

ROOT CAUSE (GDB):
  The kmem arena's extend (cave57's thunk -> 0x9ebd7be0) reads the
  kernel region-manager global [0xa1950ab8] — at runtime it holds
  DMAP(0x3F300000) (the fake kernel MAP object whose fields are garbage
  0xf000ff53 patterns) — 'mov rax, [rdi+0x20]' reads garbage and the
  downstream mutex lock (0x9e8b70xx slow path -> 0x9e81dd40) gets NULL
  from the lock-domain lookup -> 'mov rcx, [rbx+rax+0x20]' with
  rbx = rax = 0 -> CR2=0x20.
  The zero-page manager (DMAP 0x3F00D000) already has the full guard
  suite: cave47's alloc bump, cave49's insert skip, cave32's word-0
  lock CAS.

FIX — cave58 @0x9E401600 replacing [0x9ebd7bff, 0x9ebd7c06) (7B:
  'mov rdi, [rip+0x2d78eb2]'):
    rdi = [0xa1950ab8]; if rdi == DMAP(0x3F300000) (the garbage map)
    -> rdi = DMAP(0x3F00D000) (the guarded zero-page manager);
    replay 'mov rax, [rdi+0x20]'; continue 0x9ebd7c0a.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE58 = 0x9E401600
S58, S58E = 0x9EBD7BFF, 0x9EBD7C06          # mov rdi,[rip+0x2d78eb2] (7B)
GLOBAL = 0xFFFFFFFFA1950AB8
GARBAGE_MAP = 0xFFFF8E773F300000
ZERO_MGR = 0xFFFF8E773F00D000

OLD58 = bytes.fromhex("488b3db28ed702")

C58 = f"""
    movabs rdi, {GLOBAL:#x}
    mov  rdi, qword ptr [rdi]
    movabs rax, {GARBAGE_MAP:#x}
    cmp  rdi, rax
    jne  keep
    movabs rdi, {ZERO_MGR:#x}
keep:
    mov  rax, qword ptr [rdi + 0x20]
    jmp  {0xFFFFFFFF9EBD7C0A:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C58, CAVE58)
print(f"cave58: {len(code):#x}B @ {CAVE58:#x}  hook {S58:#x} ({len(OLD58)}B)")
assert len(code) <= 0x80, "cave58 too big"

img = bytearray(open(IMG, "rb").read())

off = S58 - KTEXT
site = bytes(img[off:off+len(OLD58)])
if site[:1] == b"\xe9":
    rel_expect = CAVE58 - (S58 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S58:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S58:#x}: already hooked to cave58 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD58:
        print(f"FAIL site {S58:#x}: {site.hex()} (expected {OLD58.hex()})"); sys.exit(1)
    hooked = False

off = CAVE58 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave {CAVE58:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

md = Cs(CS_ARCH_X86, CS_MODE_64)
insns = list(md.disasm(code, CAVE58))

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE58 - (S58 + 5)
    off = S58 - KTEXT
    img[off:off+len(OLD58)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD58) - 5)

print("--- cave58 ---")
for i in insns:
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP16#16: region-manager global redirect (cave58)")
