#!/usr/bin/env python3
"""WP18 #14 — the zone_create_ext NULL-keg field guard (slot @0x9E402500)
          (crash 0xffffffff9e82b57b, CR2=0x80 READ — the WP18#13 follow-on).

The zone_create_ext flow after the parent-keg resolution:
    0x9e82b552  rax = [r9+0x68]     ; the parent keg (r9=NULL -> WP18#13
                                     ; jumps the keg==NULL path)
    0x9e82b55b  rbx = [rax+0x10]    ; the keg's allocator object
    0x9e82b561  xor ebx, ebx        ; the keg==NULL path: rbx = 0
    0x9e82b563  ... the local 0x58-byte zone-desc init ...
    0x9e82b57b  mov eax, [rbx+0x80]      <<< CR2 = 0x80 (rbx = 0)
    0x9e82b581  mov [rbp-0x80], rax      ; the desc's field
  The designed keg==NULL path leaves rbx=0 and then dereferences it —
  dead code in the live kernel (every real zone has a keg); reachable
  on this boot via the NULL parent.

FIX — the LOCAL GUARD: hook [0x9e82b57b, 0x9e82b585) (10B: 'mov
  eax,[rbx+0x80]' (6B) + 'mov [rbp-0x80],rax' (4B)):
    rbx == 0  -> the desc's field := 0 (the 'no allocator' answer);
    rbx != 0  -> replay both; continue 0x9e82b585.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E402500
S = 0x9E82B57B                       # mov eax,[rbx+0x80]; mov [rbp-0x80],rax (10B)
CONT = 0xFFFFFFFF9E82B585            # mov rax,[rbp-0x90]

OLD = bytes.fromhex("8b838000000048894580")   # mov eax,[rbx+0x80]; mov [rbp-0x80],rax

C = f"""
    test rbx, rbx
    jz   nullkeg
    mov  eax, dword ptr [rbx + 0x80]
    mov  qword ptr [rbp - 0x80], rax
    jmp  {CONT:#x}
nullkeg:
    mov  qword ptr [rbp - 0x80], 0
    xor  eax, eax
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
print("--- zone_create_ext NULL-keg field guard (slot 0x9E402500) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#14: zone_create_ext NULL-keg field guard (local guard @0x9E402500)")
