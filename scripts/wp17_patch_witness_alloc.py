#!/usr/bin/env python3
"""WP17 #17 — the witness-allocation NULL-preserving store (cave77 @0x9E402080).

ROOT CAUSE (GDB wp17_gdb_c23 — the watchpoint with cave76 active):
  The DESIGNED witness allocation (0x9e81e576..0x9e81e595):
    obj = heap_alloc(0x20)                    ; the cave69/75-supplied obj
    [0xa18e6dc0] = obj
    rax = bucket_alloc(obj, 0, 2)             ; the zone-init — returns NULL
                                             ; on this boot (the never-
                                             ; initialized zone machinery)
    [thread0+0x78] = rax                      ; <<< OVERWRITES the WP17#15/16
                                             ; seed with NULL!
  The designed store of a NULL allocation result wipes the seeded
  witness head -> the next mtx-acquire's witness path reads NULL ->
  'mov rax,[rdi]' with rdi=0x18 -> CR2=0x18.

FIX — hook the store [0x9e81e595, 0x9e81e59c) (7B 'mov [thread0+0x78],
  rax'): rax == 0 -> SKIP the store (the seeded zero page stays — the
  'fresh empty witness' semantics); rax != 0 -> the designed store
  (the real allocated object wins). Then jump the designed continuation
  0x9e81e59c ('pop rbp; ret').
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE77 = 0x9E402080
S77, S77E = 0x9E81E595, 0x9E81E59C          # mov [thread0+0x78], rax (7B)
CONT77 = 0xFFFFFFFF9E81E59C                  # 'pop rbp; ret'

TD0_WITNESS = 0xFFFFFFFFA19788D8

OLD77 = bytes.fromhex("4889053ca31503")      # mov [rip+0x315a33c], rax

C77 = f"""
    test rax, rax
    jz   keep
    movabs r10, {TD0_WITNESS:#x}
    mov  qword ptr [r10], rax
keep:
    jmp  {CONT77:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C77, CAVE77)
print(f"cave77: {len(code):#x}B @ {CAVE77:#x}  hook {S77:#x} (7B)")
assert len(code) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = S77 - KTEXT
site = bytes(img[off:off+len(OLD77)])
if site[:1] == b"\xe9":
    rel_expect = CAVE77 - (S77 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S77:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S77:#x}: already hooked to cave77 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD77:
        print(f"FAIL site {S77:#x}: {site.hex()} != {OLD77.hex()}"); sys.exit(1)
    hooked = False

off = CAVE77 - KTEXT
cur = bytes(img[off:off+len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    img[off:off+0x80] = b"\xcc" * 0x80
    print(f"cave {CAVE77:#x}: stale body — blanking for rewrite")
print("site + cave assertions OK")

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE77 - (S77 + 5)
    off = S77 - KTEXT
    img[off:off+len(OLD77)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD77) - 5)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave77 (witness NULL-preserving store) ---")
for i in md.disasm(code, CAVE77):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP17#17: witness-allocation NULL-preserving store (cave77)")
