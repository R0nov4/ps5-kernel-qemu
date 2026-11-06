#!/usr/bin/env python3
"""WP17 #14 — the malloc bucket-NULL bump (cave75 @0x9E401F80)
          (the return of crash 0x9e9471ad CR2=0x8 — malloc NULL -> [NULL+8]).

ROOT CAUSE:
  With the zone-lookup validation (cave73) and WP12's cave7 entry guard,
  the malloc small path's bucket alloc now returns NULL CLEANLY for the
  unregistered-zone size classes — but the malloc's continuation
  (0x9eff8c79) never reaches the designed malloc-NULL node (0x9eff8d32,
  WP13's cave11 path — that only fires when the TYPE's zone-table itself
  is NULL; ours is a non-NULL zero bump page). The NULL flows straight
  to 'mov rax, r14; ret' -> the caller writes [NULL+8] -> CR2=0x8.

FIX — hook the NULL branch [0x9eff8c7c, 0x9eff8c81) (5B: 'test rax,rax'
  + the '74' head of 'je 0x9eff8c8b'):
    rax != 0  -> the designed continuation 0x9eff8c81
    rax == 0  -> the SHARED bump (cave50's window + state @0x3F1A0830,
                 ceiling 0x3F740000): r14 := rax := align16([rbp-0x38]
                 — the saved size)-sized object; jump 0x9eff8c8b (past
                 the 'mov eax,[rbx+0xcc]' zone-count read — rbx may be
                 the NULLed zone);
    exhaustion -> keep NULL, same skip.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE75 = 0x9E401F80
S75, S75E = 0x9EFF8C7C, 0x9EFF8C81          # test rax,rax; [74]0a (5B)
HAVE75 = 0xFFFFFFFF9EFF8C81                  # the designed continuation
SKIP75 = 0xFFFFFFFF9EFF8C8B                  # past the zone-count read

BUMP_SLOT = 0xFFFF8E773F1A0830
WIN_LO = 0xFFFF8E773F1A1000
WIN_HI = 0x3F740000

OLD75 = bytes.fromhex("4885c074")            # test rax,rax; 74

C75 = f"""
    test rax, rax
    jnz  have_obj
    movabs r10, {BUMP_SLOT:#x}
    mov  rax, qword ptr [r10]
    test rax, rax
    jnz  b1
    movabs rax, {WIN_LO:#x}
b1:
    mov  rdx, qword ptr [rbp - 0x38]
    add  rdx, 15
    and  rdx, -16
    lea  rdx, [rax + rdx]
    cmp  edx, {WIN_HI:#x}
    ja   no_mem
    mov  qword ptr [r10], rdx
    mov  r14, rax
    jmp  {SKIP75:#x}
no_mem:
    xor  eax, eax
    jmp  {SKIP75:#x}
have_obj:
    jmp  {HAVE75:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C75, CAVE75)
print(f"cave75: {len(code):#x}B @ {CAVE75:#x}  hook {S75:#x} (5B)")
assert len(code) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = S75 - KTEXT
site = bytes(img[off:off+len(OLD75)])
if site[:1] == b"\xe9":
    rel_expect = CAVE75 - (S75 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S75:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S75:#x}: already hooked to cave75 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD75:
        print(f"FAIL site {S75:#x}: {site.hex()} != {OLD75.hex()}"); sys.exit(1)
    hooked = False

off = CAVE75 - KTEXT
cur = bytes(img[off:off+len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    img[off:off+0x80] = b"\xcc" * 0x80
    print(f"cave {CAVE75:#x}: stale body — blanking for rewrite")
print("site + cave assertions OK")

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE75 - (S75 + 5)
    off = S75 - KTEXT
    img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave75 (malloc bucket-NULL bump) ---")
for i in md.disasm(code, CAVE75):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP17#14: malloc bucket-NULL bump (cave75)")
