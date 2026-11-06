#!/usr/bin/env python3
"""WP20 G3 — THE ENTROPY-DEVICE NULL SOURCE-ARRAY GUARD (the user's plan #3)
          (crash 0xffffffff9e71c9dc, CR2=0x0 READ — serial right at
           'random: entropy device external interface')

CASCADE: the entropy-source registration fn 0x9e71c9b0:
    esi = [0xa1849850]        ; the source count — live-dump RESIDUE = 7
    (esi != 0, esi <= 0xff -> the slot search:)
    rax = [rbx + 0x30]        ; the per-source counter array — NULL on this
                              ; boot (the randomdev ctx is half-initialized;
                              ; its array alloc answered the designed NULL)
    0x9e71c9dc  cmp dword ptr [rax], 0    <<< CR2 = 0x0 READ

THE USER'S FIX (verbatim): [rbx+0x30]==NULL -> jump to the DESIGNED
  empty path 0x9e71ca6b ('inc esi; mov [count], esi; cmp 0x100;
  jl 0x9e71cba6' -> the clean 5-pop RET — no further array derefs).
  The entropy device simply registers no sources; the march prints
  'mem: <memory>', 'null: <full device>' and the GEOM_SCHED stage.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E402B80                    # WP20 slot ledger (G2 used 0x9E402B00)
S = 0x9E71C9D8                       # mov rax,[rbx+0x30]; cmp [rax],0 (7B)
CONT = 0xFFFFFFFF9E71C9E5            # mov r15d,1 (the designed slot loop)
EMPTY = 0xFFFFFFFF9E71CA6B           # the designed empty path (user-specified)

OLD = bytes.fromhex("488b4330" + "833800")   # mov rax,[rbx+0x30]; cmp dword [rax],0

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

C = f"""
    mov  rax, qword ptr [rbx + 0x30]
    test rax, rax
    jz   no_array
    cmp  dword ptr [rax], 0
    je   no_array
    jmp  {CONT:#x}
no_array:
    jmp  {EMPTY:#x}
"""

code = asm(C, SLOT)
print(f"slot {SLOT:#x}: {len(code):#x}B  hook {S:#x} ({len(OLD)}B)")
assert len(code) <= 0x80

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

off = S - KTEXT
site = bytes(img[off:off+len(OLD)])
if site[:1] == b"\xe9":
    rel_expect = SLOT - (S + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S:#x}: already hooked to slot {SLOT:#x} (idempotent rewrite)")
    hooked = True
else:
    if site != OLD:
        print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
    hooked = False

off = SLOT - KTEXT
cur = bytes(img[off:off+len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    print(f"FAIL slot {SLOT:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)
print("site + slot assertions OK")

img[off:off+len(code)] = code
if not hooked:
    rel = SLOT - (S + 5)
    off = S - KTEXT
    img[off:off+len(OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD) - 5)

print("--- entropy-device NULL source-array guard (slot 0x9E402B80) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print("OK WP20-G3: entropy NULL-array guard (@0x9E71C9D8 -> slot 0x9E402B80, "
      "empty path 0x9E71CA6B) — 'mem:', 'null:', GEOM_SCHED next")
