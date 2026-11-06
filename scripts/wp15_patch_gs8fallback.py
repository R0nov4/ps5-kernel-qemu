#!/usr/bin/env python3
"""WP15 #15 — gs:[8] seed FALLBACK in the per-CPU module (crash 0x9eaa5df3 v2).

CONTEXT: the WP15#14 image-seed of pcpu+8 ([0xa1fb8f08]) does NOT survive:
the runtime pcpu initialization zeroes the struct after the image load,
so gs:[8] is NULL again by the time the AP/per-CPU module runs. The
module's get-next function 0x9eaa72b0 reads gs:[8] TWICE:
  rax-block [0x9eaa73b1,0x9eaa73d2): mov rax,gs:[8]; store per-CPU table
  rbx-block [0x9eaa73d2,0x9eaa73db): mov rbx,gs:[8]   <- the RETURN value
and the caller marks the returned object ([rax+0x400] = 4 via 0x9ea925e0
which returns it as r13) then reads [r13+0xed]/[r13+0x3c4]. NULL there =
crash (0x9eaa5df3 CR2=0xed).

FIX: replace NULL with the zero seed page at RUNTIME (where the image
seed cannot survive):
  - REWRITE cave33 @0x9E400980 (the existing hook A at 0x9eaa73b1 stays):
      rax = gs:[8]; rax == 0 -> rax = DMAP(0x3F190000); store; read
      [rax+0x3c4] (=0 on the seed); store; continue 0x9eaa73d2.
  - NEW cave36 @0x9E400B00 + hook B at [0x9eaa73d2, 0x9eaa73db):
      rbx = gs:[8]; rbx == 0 -> rbx = DMAP(0x3F190000); jmp 0x9eaa73db.
  The seed page [0x3F190000,0x3F1A0000): zero RAM in the SMAP-reserved
  window — [obj+0xed] reads 0, [obj+0x3c4] reads 0, [obj+0x400] state
  marks land in the page harmlessly.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE33  = 0x9E400980            # REWRITE (hook A at 0x9eaa73b1 already jumps here)
CAVE36  = 0x9E400B00            # NEW (hook B)
SITE_B  = 0x9EAA73D2
CONT_B  = 0xFFFFFFFF9EAA73DB
SEED    = 0xFFFF8E773F190000    # DMAP(0x3F190000)

OLD_B = bytes.fromhex("65488b1c2508000000")           # mov rbx, gs:[8] (9B)
OLD_CAVE33_HEAD = bytes.fromhex("6548a108000000000000004885c07518")  # my old cave33 head

CAVE33_ASM = f"""
    mov  rax, qword ptr gs:[8]
    test rax, rax
    jnz  ok
    movabs rax, {SEED:#x}
ok:
    mov  qword ptr [r14 + r13 + 0x4d30], rax
    movzx eax, word ptr [rax + 0x3c4]
    mov  word ptr [r14 + r13 + 0x4d38], ax
    jmp  {0xFFFFFFFF9EAA73D2:#x}
"""

CAVE36_ASM = f"""
    mov  rbx, qword ptr gs:[8]
    test rbx, rbx
    jnz  ok
    movabs rbx, {SEED:#x}
ok:
    jmp  {CONT_B:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

cave33 = asm(CAVE33_ASM, CAVE33)
cave36 = asm(CAVE36_ASM, CAVE36)
print(f"cave33 (new): {len(cave33):#x}B @ {CAVE33:#x}   cave36: {len(cave36):#x}B @ {CAVE36:#x}")
assert len(cave33) <= 0x80 and len(cave36) <= 0x80

img = bytearray(open(IMG, "rb").read())

# verify: hook A still jumps to cave33; old cave33 head present; site B pristine
off = 0x9EAA73B1 - KTEXT
hook_a = bytes(img[off:off+5])
rel_expect = CAVE33 - (0x9EAA73B1 + 5)
if hook_a != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
    print(f"FAIL hook A not pointing at cave33: {hook_a.hex()}"); sys.exit(1)
off = CAVE33 - KTEXT
if bytes(img[off:off+len(OLD_CAVE33_HEAD)]) != OLD_CAVE33_HEAD:
    print("FAIL old cave33 head not found"); sys.exit(1)
off = SITE_B - KTEXT
if bytes(img[off:off+len(OLD_B)]) != OLD_B:
    print(f"FAIL site B: {bytes(img[off:off+len(OLD_B)]).hex()} != {OLD_B.hex()}"); sys.exit(1)
off = CAVE36 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print("FAIL cave36 not pristine CC"); sys.exit(1)
print("assertions OK")

# rewrite cave33 body (blank the old 0x50 bytes first, then write)
off = CAVE33 - KTEXT
img[off:off+0x50] = b"\xcc" * 0x50
img[off:off+len(cave33)] = cave33

# hook B -> cave36
rel = CAVE36 - (SITE_B + 5)
off = SITE_B - KTEXT
img[off:off+len(OLD_B)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD_B) - 5)

# write cave36
off = CAVE36 - KTEXT
img[off:off+len(cave36)] = cave36

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave33 (new) ---")
for i in md.disasm(cave33, CAVE33):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
print("--- cave36 ---")
for i in md.disasm(cave36, CAVE36):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP15#15: gs:[8] runtime seed fallback (cave33 rewrite + cave36)")
