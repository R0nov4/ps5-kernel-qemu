#!/usr/bin/env python3
"""WP18 #3 — the cpuset-root refcount NULL skip (slot @0x9E401D80)
          (crash 0xffffffff9ec2c374, CR2=0x8 WRITE via refcount(NULL)).

CASCADE (GDB wp18_gdb_c1): WP18#2 made the cpuset-zone bootstrap return its
  designed NULL answer -> the SYSINIT caller stored it at [0xa19788c0]
  (the root cpuset object global) -> the NEXT SYSINIT helper (0x9efd9a80):
    0x9efd9a84  mov rdi, [0xa19788c0]     ; the root object — NULL now
    0x9efd9a8b  call 0x9ec2c370           ; refcount: 'lock add [rdi+8],1' -> CR2=0x8
    0x9efd9a90  mov [0xa0fe65c0], rax     ; the ref'd root
    0x9efd9ab1  mov eax, [0x9fe74070]     ; a static field
    0x9efd9ab3  mov [0xa0fe6634], eax     ; copy
    pop rbp; ret
  'lock add [NULL+8], 1' faults.

FIX — the LOCAL GUARD: hook the load [0x9efd9a84, 0x9efd9a8b) (7B
  rip-relative 'mov rdi,[0xa19788c0]'):
    replay the load (movabs + deref — the rip-relative can not be replayed
    verbatim from the cave);
    rdi == 0  -> the cpuset subsystem was never created: the whole helper
                 is a no-op -> 'pop rbp; ret' (the prologue already ran;
                 the frame is balanced; nothing was written);
    rdi != 0  -> jmp 0x9efd9a8b (the designed refcount + the rest).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E401D80                    # the old cave71 slot, freed by the rollback
S = 0x9EFD9A84                       # mov rdi,[rip+0x299ee35] (7B)
ROOT = 0xFFFFFFFFA19788C0            # the root cpuset object global
CONT = 0xFFFFFFFF9EFD9A8B            # the refcount call

OLD = bytes.fromhex("488b3d35ee9902")   # mov rdi, qword ptr [rip + 0x299ee35]

C = f"""
    movabs rdi, {ROOT:#x}
    mov    rdi, qword ptr [rdi]
    test   rdi, rdi
    jz     nullret
    jmp    {CONT:#x}
nullret:
    pop    rbp
    ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C, SLOT)
print(f"slot 0x{SLOT:x}: {len(code):#x}B  hook {S:#x} (7B)")
assert len(code) <= 0x80

img = bytearray(open(IMG, "rb").read())

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
print("--- cpuset-root refcount NULL skip (slot 0x9E401D80) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#3: cpuset-root refcount NULL skip (local guard @0x9E401D80)")
