#!/usr/bin/env python3
"""WP17 #18 — the witness list-append NULL-tail guard (cave78 @0x9E402100)
          (crash 0xffffffff9e81d943, CR2=0x0 WRITE).

ROOT CAUSE:
  The witness list-append (the mtx-acquire's bookkeeping):
    rdx = [r12 + class*16 + 0x28]          ; the list's TAIL slot
    [rbx + 0x48] = rdx                     ; new->prev-tail
    [rdx] = rbx                            ; <<< rdx = NULL (the seeded
                                           ;     zero witness page's empty
                                           ;     list) -> write [0]!
    [r12 + class*16 + 0x28] = rbx + 0x40   ; the new tail
  The DESIGNED empty-list append must NOT store into the NULL tail:
  skipping '[rdx] = rbx' leaves a VALID single-element list
  (new->prev-tail == NULL — the end marker), and the head/tail update
  proceeds — the list self-heals on the next append.

FIX — hook [0x9e81d943, 0x9e81d948) (5B: 'mov [rdx],rbx' (3B) + the
  '49' REX head of 'mov [r12+rcx+0x28],rax'):
    rdx == 0 -> skip the tail store (the designed empty case);
    rdx != 0 -> replay both stores;
  both paths run the head/tail update -> 0x9e81d94b.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE78 = 0x9E402100
S78, S78E = 0x9E81D943, 0x9E81D948          # mov [rdx],rbx; [49]8944.. (5B)
CONT78 = 0xFFFFFFFF9E81D94B                  # 'test r13,r13'

OLD78 = bytes.fromhex("48891a49")            # mov [rdx],rbx; 49

C78 = f"""
    test rdx, rdx
    jz   skip
    mov  qword ptr [rdx], rbx
skip:
    mov  qword ptr [r12 + rcx + 0x28], rax
    jmp  {CONT78:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C78, CAVE78)
print(f"cave78: {len(code):#x}B @ {CAVE78:#x}  hook {S78:#x} (5B)")
assert len(code) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = S78 - KTEXT
site = bytes(img[off:off+len(OLD78)])
if site[:1] == b"\xe9":
    rel_expect = CAVE78 - (S78 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S78:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S78:#x}: already hooked to cave78 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD78:
        print(f"FAIL site {S78:#x}: {site.hex()} != {OLD78.hex()}"); sys.exit(1)
    hooked = False

off = CAVE78 - KTEXT
cur = bytes(img[off:off+len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    img[off:off+0x80] = b"\xcc" * 0x80
    print(f"cave {CAVE78:#x}: stale body — blanking for rewrite")
print("site + cave assertions OK")

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE78 - (S78 + 5)
    off = S78 - KTEXT
    img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave78 (witness append NULL-tail guard) ---")
for i in md.disasm(code, CAVE78):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP17#18: witness list-append NULL-tail guard (cave78)")
