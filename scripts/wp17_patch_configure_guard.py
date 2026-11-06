#!/usr/bin/env python3
"""WP17 #11 — the configure-accessor NULL-lock-container guard
          (cave71 @0x9E401D80; crash 0xffffffff9e8b6a2d, CR2=0x18).

ROOT CAUSE (GDB wp17_gdb_c10):
  The sysctl-leaf registration (caller 0x9eff9b59 — WP13#3's family)
  now gets a REAL context object (cave69's import-failure bump made the
  heap alloc succeed) and calls the configure accessor 0x9e829610(obj,
  value):
    r14 = obj; rdi = [obj+0x40]     ; the lock container
    mtx_lock(rdi+0x18)              ; <<< [obj+0x40] = NULL (fresh bump
                                    ;     memory) -> rdi = 0x18 -> CR2=0x18
    [obj+0x170] = value; mtx_unlock(...)
  The fresh bump object's +0x40 field was never initialized — the
  designed init (the zone-create machinery) never ran on this boot.

FIX — hook [0x9e82961a, 0x9e82961f) (5B: 'mov rdi,[rdi+0x40]' + the REX
  of 'mov rbx,rsi'): a NULL lock container -> the void skip (replicate
  the fn's own epilogue pops + ret); else replay the load and the
  'mov rbx,rsi', continue 0x9e829621 (the designed lock/write/unlock).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE71 = 0x9E401D80
S71, S71E = 0x9E82961A, 0x9E82961F          # mov rdi,[rdi+0x40]; [48]89f3 (5B)
CONT71 = 0xFFFFFFFF9E829621                  # xor esi,esi (the designed lock flow)

OLD71 = bytes.fromhex("488b7f4048")          # mov rdi,[rdi+0x40]; 48

C71 = f"""
    mov  rdi, qword ptr [rdi + 0x40]
    test rdi, rdi
    jz   nullret
    mov  rbx, rsi
    jmp  {CONT71:#x}
nullret:
    pop  rbx
    pop  r14
    pop  rbp
    ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C71, CAVE71)
print(f"cave71: {len(code):#x}B @ {CAVE71:#x}  hook {S71:#x} (5B)")
assert len(code) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = S71 - KTEXT
site = bytes(img[off:off+len(OLD71)])
if site[:1] == b"\xe9":
    rel_expect = CAVE71 - (S71 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S71:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S71:#x}: already hooked to cave71 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD71:
        print(f"FAIL site {S71:#x}: {site.hex()} != {OLD71.hex()}"); sys.exit(1)
    hooked = False

off = CAVE71 - KTEXT
cur = bytes(img[off:off+len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    print(f"FAIL cave {CAVE71:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)
print("site + cave assertions OK")

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE71 - (S71 + 5)
    off = S71 - KTEXT
    img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave71 (configure NULL-lock guard) ---")
for i in md.disasm(code, CAVE71):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP17#11: configure-accessor NULL-lock-container guard (cave71)")
