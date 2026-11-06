#!/usr/bin/env python3
"""WP18 #11 — the zone-stats accessor NULL-zone guard (slot @0x9E402200)
          (crash 0xffffffff9e82d1db, CR2=0x68 READ).

CASCADE (GDB wp18_gdb_c4): the SYSINIT zone-create flow at 0x9e81b07e:
    rax = zone_create(0x9e82b0e0)(...)   <- NULL on this boot
    rdi = rax ; [0xa18e5020] = rax
    esi = [0xa18e5040] ; esi > 0 ->
    call 0x9e82d1d0 (the zone-stats accessor) with rdi = NULL
    0x9e82d1db  mov rax, [rdi + 0x68]     <<< CR2 = 0x68 READ
  The accessor walks zone->[0x68]->[0x10] and computes stats (idiv/imul);
  its DESIGNED empty path exists at 0x9e82d248 ('mov eax,ebx(=0); the
  5-pop epilogue; ret') — reached when the inner pointers are NULL.

FIX — the LOCAL GUARD (the designed empty answer for the NULL zone):
  hook [0x9e82d1db, 0x9e82d1e1) (6B: 'mov rax,[rdi+0x68]' (4B) + 'xor
  ebx,ebx' (2B) — a 4-byte site is too short for the 5-byte e9 hook, so
  BOTH displaced instructions are replayed in the cave):
    rdi == 0  -> xor ebx,ebx; jmp the designed empty path 0x9e82d248
                 (eax = 0 — the same answer the designed NULL-walk gives);
    rdi != 0  -> replay 'mov rax,[rdi+0x68]; xor ebx,ebx'; jmp 0x9e82d1e1
                 ('test rax,rax' — the designed walk).
  Generic for all 6+ callers of the accessor (0x9e730446, 0x9e76a6a0,
  0x9e7ddc62, 0x9e81ac14, 0x9e81ad8a, 0x9e81ae2a, ...).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E402200                    # fresh slot (the ledger's next free)
S = 0x9E82D1DB                       # mov rax,[rdi+0x68]; xor ebx,ebx (6B)
CONT = 0xFFFFFFFF9E82D1E1            # test rax,rax (the designed walk)
EMPTY = 0xFFFFFFFF9E82D248           # the designed empty path (eax=0; epilogue)

OLD = bytes.fromhex("488b476831db")  # mov rax,[rdi+0x68]; xor ebx,ebx

C = f"""
    test rdi, rdi
    jz   nullzone
    mov  rax, qword ptr [rdi + 0x68]
    xor  ebx, ebx
    jmp  {CONT:#x}
nullzone:
    xor  ebx, ebx
    jmp  {EMPTY:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C, SLOT)
print(f"slot 0x{SLOT:x}: {len(code):#x}B  hook {S:#x} (6B)")
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

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- zone-stats accessor NULL-zone guard (slot 0x9E402200) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#11: zone-stats accessor NULL-zone guard (local guard @0x9E402200)")
