#!/usr/bin/env python3
"""WP17 #10 — the panic-path NULL-device guard (cave70 @0x9E401D00)
          (kills the 119x recursive 'panic during panic' spiral).

ROOT CAUSE:
  After the first trap the panic/dump path faults at 0x9e9f9896
  ('mov rcx, [rdi+0x80]' — the mDBG/console device capability read)
  with rdi = NULL — the dump machinery's device object was never
  created on this boot. The fault re-traps INSIDE the panic path ->
  'panic during panic' -> 119 recursive dumps, each ~800B deeper on
  thread0's stack, until the stack exhausts (~95KB) — the serial fills
  with 120 identical trap blocks and the boot hangs in the spiral.

FIX — hook the capability-leaf's entry [0x9e9f9896, 0x9e9f989d)
  (7B 'mov rcx,[rdi+0x80]'):
    rdi == 0 -> return 0 (the 'no capabilities' answer — the same
                clean answer a fully-zeroed device would give);
    else     -> replay the load, continue 0x9e9f989d.
  Panics now complete their single dump + power down instead of spiraling.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE70 = 0x9E401D00
S70, S70E = 0x9E9F9896, 0x9E9F989D          # mov rcx,[rdi+0x80] (7B)
CONT70 = 0xFFFFFFFF9E9F989D                  # the flags tests

OLD70 = bytes.fromhex("488b8f80000000")     # mov rcx,[rdi+0x80]

C70 = f"""
    test rdi, rdi
    jz   nullret
    mov  rcx, qword ptr [rdi + 0x80]
    jmp  {CONT70:#x}
nullret:
    xor  eax, eax
    ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C70, CAVE70)
print(f"cave70: {len(code):#x}B @ {CAVE70:#x}  hook {S70:#x} (7B)")
assert len(code) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = S70 - KTEXT
site = bytes(img[off:off+len(OLD70)])
if site[:1] == b"\xe9":
    rel_expect = CAVE70 - (S70 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S70:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S70:#x}: already hooked to cave70 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD70:
        print(f"FAIL site {S70:#x}: {site.hex()} != {OLD70.hex()}"); sys.exit(1)
    hooked = False

off = CAVE70 - KTEXT
cur = bytes(img[off:off+len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    print(f"FAIL cave {CAVE70:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)
print("site + cave assertions OK")

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE70 - (S70 + 5)
    off = S70 - KTEXT
    img[off:off+len(OLD70)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD70) - 5)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave70 (panic-path NULL-device guard) ---")
for i in md.disasm(code, CAVE70):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP17#10: panic-path NULL-device guard (cave70)")
