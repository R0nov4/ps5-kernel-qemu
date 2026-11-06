#!/usr/bin/env python3
"""WP18 #4 — the zone-create NULL-return guard (slot @0x9E401E00)
          (crash 0xffffffff9ee1e9d0, CR2=0x40 WRITE; 'filedesc structure').

CASCADE (GDB wp18_gdb_c2b): the post-APIC SYSINIT registers the malloc
  TYPE 'filedesc structure' via the uma_zcreate-style fn 0x9eb1cde0
  (called from the SYSINIT walker 0x9e926a50):
    0x9eb1cdee  rdi = [0xa1d71eb0]          ; the master zone-of-zones table
                                             ; — ZERO on this boot (the UMA
                                             ; bootstrap never ran)
    0x9eb1cdff  rax = bucket_alloc(rdi, 0, 0x102)   <- NULL (NULL zone +
                                                       never-initialized import)
    0x9eb1ce04  rdi = rax + 0x40            <- NULL+0x40 = 0x40
    0x9eb1ce08  rsi = 'filedesc structure'
    0x9eb1ce14  call 0x9f03b290             ; the zone-object sub-init:
                ... 'mov [rdi],rdx' @0x9ee1e9d0  <<< CR2 = 0x40 WRITE
  The sub-init writes the type-name + flags into the FRESH ZONE OBJECT
  which was never allocated.

FIX — the LOCAL GUARD (the allocators keep their designed NULL-on-failure
  answer): hook the bucket_alloc call itself [0x9eb1cdff, 0x9eb1ce04)
  (5B 'call 0x9e82b880'):
    replay the call in the cave;
    rax == 0  -> the zone-object allocation failed: return the designed
                 NULL from fn 0x9eb1cde0 — xor eax,eax; jmp its own
                 epilogue-tail 0x9eb1cf2e (pop rbx; pop r12; pop r14;
                 pop r15; pop rbp; ret — the 5 prologue pushes are all
                 on the stack at the hook point, rbx/r12/r14/r15 hold
                 only caller-saved garbage that the pops restore);
    rax != 0  -> jmp 0x9eb1ce04 (the designed zone-object init).
  The 4 mapped callers: the SYSINIT walker stores rax -> [0xa1978f40]
  (NULL-safe); 0x9f0a1723/0x9f0a20aa store to stack locals (NULL-safe);
  0x9eb1d0ee writes [rax+0x2c] (a different flow — not in this march;
  will be guarded locally if it ever appears).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E401E00                    # the old cave72 slot, freed by the rollback
S = 0x9EB1CDFF                       # call 0x9e82b880 (5B)
BUCKET = 0xFFFFFFFF9E82B880          # the bucket allocator
CONT = 0xFFFFFFFF9EB1CE04            # lea rdi,[rax+0x40] (the designed path)
EPILOG = 0xFFFFFFFF9EB1CF2E          # pop rbx; pop r12; pop r14; pop r15; pop rbp; ret

OLD = bytes.fromhex("e87cead0ff")    # call 0x9e82b880

C = f"""
    call {BUCKET:#x}
    test rax, rax
    jz   alloc_failed
    jmp  {CONT:#x}
alloc_failed:
    xor  eax, eax
    jmp  {EPILOG:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C, SLOT)
print(f"slot 0x{SLOT:x}: {len(code):#x}B  hook {S:#x} (5B)")
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
    img[off:off+len(OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- zone-create NULL-return guard (slot 0x9E401E00) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#4: zone-create NULL-return guard (local guard @0x9E401E00)")
