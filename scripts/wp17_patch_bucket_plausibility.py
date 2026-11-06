#!/usr/bin/env python3
"""WP17 #12 — the zone-bucket-slot plausibility guard (cave72 @0x9E401E00)
          (crash 0xffffffff9e82b933, CR2=0xbe4b47 READ).

ROOT CAUSE (GDB wp17_gdb_c14):
  The malloc small path (0x9eff8c6b: the zone lookup over the static
  class table + the malloc TYPE's zone-table [ctx+0x18] — a fresh ZERO
  bump page on this boot) resolves a DESIGNED STATIC zone
  (0xa0fec510) whose per-CPU bucket slot [zone+0x180] still holds the
  PRISTINE non-pointer pair { [r14]=0x00000000ffffffff, [r14+8]=0xbe4b37 }
  (identical in the live dump — the designed buckets are runtime objects
  the zone-init SYSINIT creates; it never ran here).
  The bucket walk then does 'movzx ecx, [rax+0x10]' with rax = 0xbe4b37
  -> CR2 = 0xbe4b47; the r12 side (0xffffffff) would fault at [r12+2]
  on the 0x9e82b953 path the same way.

FIX — hook the walk head [0x9e82b927, 0x9e82b92c) (5B: 'mov r12,[r14]'
  + the head of 'mov rax,[r14+8]'):
    - replay both loads;
    - plausibility: kernel/DMAP pointers have bits 63..48 == 0xffff —
      a bucket value WITHOUT it (0xbe4b37, the 32-bit 0xffffffff, small
      integers) is a non-pointer:
        rax implausible -> sanitize the slot ([r14+8] := 0) + rax := 0
        r12 implausible -> r12 := 0
    - replay 'test rax,rax' and jump 0x9e82b930 (the designed 'je' uses
      the cave's flags) — the designed empty/recycle paths take over
      (the import path -> cave56/cave69's bumps supply the memory).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE72 = 0x9E401E00
S72, S72E = 0x9E82B927, 0x9E82B92C          # mov r12,[r14]; [49 8b]46 08 (5B)
JE72 = 0xFFFFFFFF9E82B92E                    # the designed 'test rax,rax' (the je follows, using its flags)

OLD72 = bytes.fromhex("4d8b26498b")          # mov r12,[r14]; 49 8b

C72 = f"""
    mov  r12, qword ptr [r14]
    mov  rax, qword ptr [r14 + 8]
    mov  rdx, rax
    shr  rdx, 48
    cmp  edx, 0xffff
    je   rax_ok
    mov  qword ptr [r14 + 8], 0
    xor  eax, eax
rax_ok:
    mov  rdx, r12
    shr  rdx, 48
    cmp  edx, 0xffff
    je   done
    xor  r12d, r12d
done:
    test rax, rax
    jmp  {JE72:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C72, CAVE72)
print(f"cave72: {len(code):#x}B @ {CAVE72:#x}  hook {S72:#x} (5B)")
assert len(code) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = S72 - KTEXT
site = bytes(img[off:off+len(OLD72)])
if site[:1] == b"\xe9":
    rel_expect = CAVE72 - (S72 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S72:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S72:#x}: already hooked to cave72 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD72:
        print(f"FAIL site {S72:#x}: {site.hex()} != {OLD72.hex()}"); sys.exit(1)
    hooked = False

off = CAVE72 - KTEXT
cur = bytes(img[off:off+len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    # v1 body present (the off-by-one jump) — blank and rewrite
    if cur[:5] == bytes.fromhex("4d8b26498b"):
        img[off:off+0x80] = b"\xcc" * 0x80
        print(f"cave {CAVE72:#x}: v1 body found — blanking for rewrite")
    else:
        print(f"FAIL cave {CAVE72:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)
print("site + cave assertions OK")

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE72 - (S72 + 5)
    off = S72 - KTEXT
    img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave72 (bucket-slot plausibility guard) ---")
for i in md.disasm(code, CAVE72):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP17#12: zone-bucket-slot plausibility guard (cave72)")
