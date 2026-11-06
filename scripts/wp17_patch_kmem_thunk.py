#!/usr/bin/env python3
"""WP17 #2 — kmem arena extend-thunk fallback (cave65 @0x9E401980).

ROOT CAUSE (GDB wp17_gdb_c2):
  The kmem alloc slow path (0x9e9d67c0) reads the arena's extend thunk:
    0x9e9d6ad5  mov r8, [r13+0x428]           ; r13 = the arena (0xa1ab6f00)
    0x9e9d6adc  lea rax, [0x9e65bf90]         ; the 3-slot thunk array END
    0x9e9d6ae3  sub rax, r8 ; ror rax,3 ; cmp rax,2 ; ja wait-path
    0x9e9d6b09  call r8                        ; the extend (rsi = size)
  Valid thunks = [0x9e65bf80, 0x9e65bf90] step 8 — the WP14 thunk 0x9E65BF80
  (-> 0x9ebd7be0 -> cave22's pool serve) is EXACTLY slot k=2.
  On this boot the thunk is NULL AGAIN at the 0xF4000 request: WP16#15's
  cave57 seeded it at the wait-fail block, but a later SYSINIT stage WIPED
  the kmem arena struct — so every kmem alloc after the wipe re-enters the
  wait path (WP14-C's flip -> the designed 0xc error) and the large mallocs
  fail -> the drain-unwind crash (fixed by WP17#1) and no 1MB objects.

FIX — the read-time fallback (WP15#15's gs:[8] runtime-seed pattern):
  cave65 hooking [0x9e9d6ad5, 0x9e9d6adc) ('mov r8,[r13+0x428]', 7B):
    r8 != 0 -> replay the load, jump the designed validation 0x9e9d6adc
    r8 == 0 -> r8 := 0x9E65BF80 (the sanctioned WP14 thunk), same jump —
               the DESIGNED validation then legitimizes the substitution
               (0x9e65bf90-0x9E65BF80 = 0x10 -> ror3 = 2 <= 2 -> PASS) and
               the extend call draws real memory from the shared 14MB pool.
  Every arena (wiped or fresh) now self-heals at the read — the whole
  'failed to allocate waiting allocation' family is systemically healthy,
  and cave57's wait-fail seeding stays as the belt-and-braces safety net.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE65 = 0x9E401980
S65, S65E = 0x9E9D6AD5, 0x9E9D6ADC          # mov r8,[r13+0x428] (7B)
CONT65 = 0xFFFFFFFF9E9D6ADC                  # the designed validation head
THUNK = 0xFFFFFFFF9E65BF80                   # the WP14 thunk (valid slot k=2)

OLD65 = bytes.fromhex("4d8b8528040000")      # mov r8,[r13+0x428]

C65 = f"""
    mov  r8, qword ptr [r13 + 0x428]
    test r8, r8
    jnz  have_thunk
    movabs r8, {THUNK:#x}
have_thunk:
    jmp  {CONT65:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C65, CAVE65)
print(f"cave65: {len(code):#x}B @ {CAVE65:#x}  hook {S65:#x} (7B)")
assert len(code) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = S65 - KTEXT
site = bytes(img[off:off+len(OLD65)])
if site[:1] == b"\xe9":
    rel_expect = CAVE65 - (S65 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S65:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S65:#x}: already hooked to cave65 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD65:
        print(f"FAIL site {S65:#x}: {site.hex()} != {OLD65.hex()}"); sys.exit(1)
    hooked = False

off = CAVE65 - KTEXT
cur = bytes(img[off:off+len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    print(f"FAIL cave {CAVE65:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE65 - (S65 + 5)
    off = S65 - KTEXT
    img[off:off+len(OLD65)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD65) - 5)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave65 ---")
for i in md.disasm(code, CAVE65):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP17#2: kmem arena extend-thunk read-time fallback (cave65)")
