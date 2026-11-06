#!/usr/bin/env python3
"""WP20 G11 — THE STATS-TABLE NULL GUARD  [NEW FRONTIER]
          (Fatal trap 12 @ 0xffffffff9edd4209, CR2=0x177b8 READ — after
           '[MP3] failed to init message thread' — a counter query on a
           never-allocated stats table)

CASCADE: the counter-lookup fn 0x9edd41d0 (the post-MP3 reporting path):
      lock([0xa1f9a4a0])
      rax = [0xa1f9a538]              ; the stats table — NULL on this
                                      ; boot (its allocation answered
                                      ; the designed NULL)
      cmp rbx, 0x20000 ; jl 0x9edd4209
      0x9edd4209  mov ebx, [rax + rbx*4]   <<< CR2 = rbx*4 = 0x177b8 READ
      unlock; return ebx
  The table is indexed by a counter id — with no table there is no
  counter: the designed empty value is 0.

FIX — THE LOCAL GUARD: hook [0x9edd41eb, +7) (the table load):
    rax == NULL -> ebx = 0; jmp 0x9edd420c (the fn's OWN unlock +
                   return path — the designed empty answer)
    rax != NULL -> replay the load -> 0x9edd41f2 (the designed lookup)
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E403480                    # WP20 slot ledger (G10 used 0x9E403400)
S = 0x9EDD41EB                       # mov rax, [0xa1f9a538] (7B)
CONT = 0xFFFFFFFF9EDD41F2            # cmp rbx, 0x20000
UNLOCK = 0xFFFFFFFF9EDD420C          # the unlock + return path
OLD = bytes.fromhex("488b0546631c03")
TBL = 0xFFFFFFFFA1F9A538

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

C = f"""
    movabs r10, {TBL:#x}
    mov    rax, qword ptr [r10]
    test   rax, rax
    jnz    have_table
    xor    ebx, ebx
    jmp    {UNLOCK:#x}
have_table:
    jmp    {CONT:#x}
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
    hooked = True
else:
    if site != OLD:
        print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
    hooked = False

off = SLOT - KTEXT
cur = bytes(img[off:off+len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    print(f"FAIL slot {SLOT:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)

img[off:off+len(code)] = code
if not hooked:
    rel = SLOT - (S + 5)
    off = S - KTEXT
    img[off:off+len(OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD) - 5)

print("--- stats-table NULL guard (slot 0x9E403480) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

# ---------------- the WRITE twin: counter-add fn 0x9edd5030 --------------------
# (Fatal trap 12 @ 0xffffffff9edd506e, CR2=0x177b8 WRITE — the counter-
#  INCREMENT twin, same never-allocated table [0xa1f9a538]; with no
#  table there is no counter to increment: the silent no-op.)
SLOT2 = 0x9E403500
S2 = 0x9EDD504E                       # mov rax, [0xa1f9a538] (7B)
CONT2 = 0xFFFFFFFF9EDD5055            # cmp r14, 0x20000
UNLOCK2 = 0xFFFFFFFF9EDD5072          # the fn's own unlock tail
OLD2 = bytes.fromhex("488b05e3541c03")

C2 = f"""
    movabs r10, {TBL:#x}
    mov    rax, qword ptr [r10]
    test   rax, rax
    jnz    have_table2
    jmp    {UNLOCK2:#x}
have_table2:
    jmp    {CONT2:#x}
"""

code2 = asm(C2, SLOT2)
assert len(code2) <= 0x80

off = S2 - KTEXT
site = bytes(img[off:off+len(OLD2)])
if site[:1] == b"\xe9":
    rel_expect = SLOT2 - (S2 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S2:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    hooked = True
else:
    if site != OLD2:
        print(f"FAIL site {S2:#x}: {site.hex()} != {OLD2.hex()}"); sys.exit(1)
    hooked = False

off = SLOT2 - KTEXT
cur = bytes(img[off:off+len(code2)])
if not all(b == 0xCC for b in cur) and cur != code2:
    print(f"FAIL slot {SLOT2:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)

img[off:off+len(code2)] = code2
if not hooked:
    rel = SLOT2 - (S2 + 5)
    off = S2 - KTEXT
    img[off:off+len(OLD2)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD2) - 5)

print("--- stats-table WRITE twin guard (slot 0x9E403500) ---")
for i in md.disasm(code2, SLOT2):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print("OK WP20-G11: stats-table NULL guards, read + write twins (@0x9EDD41EB + @0x9EDD504E)")
