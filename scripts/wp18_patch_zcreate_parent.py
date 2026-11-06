#!/usr/bin/env python3
"""WP18 #13 — the zone_create_ext NULL-parent guard (slot @0x9E402480)
          (crash 0xffffffff9e82b552, CR2=0x68 READ).

CASCADE (GDB wp18_gdb_c5): the SYSINIT zone-setup family:
    zone_create #1 (0x9e82b0e0) -> [0xa18e5020] = NULL (the master zone
    table [0xa1d71eb0] is zero — WP18#4's guarded failure)
    ...
    0x9e81b13c  r9 = [0xa18e5020]      ; the PARENT zone — NULL
    0x9e81b166  call 0x9e82b520        ; zone_create_ext(name, ..., parent=r9)
    0x9e82b552  mov rax, [r9 + 0x68]   <<< CR2 = 0x68 (parent = NULL)
    0x9e82b556  test rax, rax
    0x9e82b559  je 0x9e82b561          ; the designed no-keg path
  The designed NULL-parent flow EXISTS at 0x9e82b561 ('xor ebx,ebx; the
  local 0x58-byte struct init ...') — the je's own target.

FIX — the LOCAL GUARD: hook [0x9e82b552, 0x9e82b559) (7B: 'mov
  rax,[r9+0x68]' + 'test rax,rax'):
    r9 == 0  -> jmp the designed no-parent path 0x9e82b561 (the same
                target the designed je reaches with a NULL parent keg);
    r9 != 0  -> replay the load + the test; jmp 0x9e82b559 (the designed
                je consumes the cave's flags).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E402480
S = 0x9E82B552                       # mov rax,[r9+0x68]; test rax,rax (7B)
CONT = 0xFFFFFFFF9E82B559            # the designed je (reads the flags)
NOPARENT = 0xFFFFFFFF9E82B561        # the designed no-parent path

OLD = bytes.fromhex("498b41684885c0")   # mov rax,[r9+0x68]; test rax,rax

C = f"""
    test r9, r9
    jz   noparent
    mov  rax, qword ptr [r9 + 0x68]
    test rax, rax
    jmp  {CONT:#x}
noparent:
    jmp  {NOPARENT:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C, SLOT)
print(f"slot 0x{SLOT:x}: {len(code):#x}B  hook {S:#x} ({len(OLD)}B)")
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
print("--- zone_create_ext NULL-parent guard (slot 0x9E402480) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#13: zone_create_ext NULL-parent guard (local guard @0x9E402480)")
