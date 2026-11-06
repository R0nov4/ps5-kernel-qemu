#!/usr/bin/env python3
"""WP18 #15 — the zone_create_ext NULL-keg flags guard (slot @0x9E402580)
          (crash 0xffffffff9e82b59c, CR2=0x70 — the WP18#14 follow-on).

The same zone-desc init stretch continues dereferencing the keg's
  allocator object (rbx = 0 on this boot):
    0x9e82b59c  mov eax, [rbx+0x70]     ; flags field 1   <<< CR2=0x70
    0x9e82b59f  mov [rbp-0x38], eax
    0x9e82b5a2  mov eax, 0x200
    0x9e82b5a7  or  eax, [rbx+0xd0]     ; flags field 2
    0x9e82b5ad  cmp [0xa18ea6f4], 1     ; (past the stretch)
    0x9e82b5b4  mov [rbp-0x34], eax     ; the OR result
    0x9e82b5b7  mov [rbp-0x40], rbx     ; the allocator ptr (0 — a plain store)

FIX — the LOCAL GUARD over the whole stretch [0x9e82b59c, 0x9e82b5ad)
  (17B, all four displaced instructions replayed):
    rbx == 0  -> [rbp-0x38] := 0; eax := 0x200 (no flags OR'd) -> 0x9e82b5ad;
    rbx != 0  -> replay the 4 instructions verbatim -> 0x9e82b5ad.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E402580
S = 0x9E82B59C                       # mov eax,[rbx+0x70] .. or eax,[rbx+0xd0] (17B)
CONT = 0xFFFFFFFF9E82B5AD            # cmp dword [0xa18ea6f4],1

OLD = bytes.fromhex("8b43708945c8b8000200000b83d0000000")

C = f"""
    test rbx, rbx
    jz   nullkeg
    mov  eax, dword ptr [rbx + 0x70]
    mov  dword ptr [rbp - 0x38], eax
    mov  eax, 0x200
    or   eax, dword ptr [rbx + 0xd0]
    jmp  {CONT:#x}
nullkeg:
    mov  dword ptr [rbp - 0x38], 0
    mov  eax, 0x200
    jmp  {CONT:#x}
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
print("--- zone_create_ext NULL-keg flags guard (slot 0x9E402580) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#15: zone_create_ext NULL-keg flags guard (local guard @0x9E402580)")
