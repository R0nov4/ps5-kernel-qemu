#!/usr/bin/env python3
"""WP18 #7 — the create_init fork tolerance (slot @0x9E401F80)
          (panic 'cannot fork init: 12').

CASCADE: fork1's designed ENOMEM (WP18#5) propagates -> create_init's
  designed panic 0x9e9275d5 ('cannot fork init: %d'):
    0x9e92742b  call 0x9f0a1430        ; fork1 -> eax = 0xc
    0x9e927430  test eax, eax
    0x9e927432  jne 0x9e9275bf         ; -> the panic block
    0x9e927438  ... the success body (pfind/register the new init proc)
    0x9e9275ac  canary check
    0x9e9275b2  add rsp,0x40; pop rbx; pop r12; pop r14; pop r15; pop rbp; ret
  The init process cannot be created on this boot (the proc-zone table
  [0xa1979e30] is zero — the zone machinery never initialized).

FIX — the LOCAL GUARD: hook the fork1 call [0x9e92742b, 0x9e927430)
  (5B 'call 0x9f0a1430'):
    replay the call in the cave;
    eax == 0  -> jmp 0x9e927430 (the designed success body);
    eax != 0  -> tolerate: xor eax,eax; jmp the fn's own success
                 EPILOGUE 0x9e9275b2 (the 5-push + sub-0x40 frame is
                 balanced at the hook point) — both the panic block AND
                 the success body (which dereferences the never-created
                 proc) are skipped; the SYSINIT march continues.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E401F80                    # the old cave75 slot, freed by the rollback
S = 0x9E92742B                       # call 0x9f0a1430 (5B)
FORK1 = 0xFFFFFFFF9F0A1430
CONT = 0xFFFFFFFF9E927430            # test eax,eax
EPILOG = 0xFFFFFFFF9E9275B2          # add rsp,0x40; pop rbx; pop r12; pop r14; pop r15; pop rbp; ret

OLD = bytes.fromhex("e800a07700")    # call 0x9f0a1430

C = f"""
    call {FORK1:#x}
    test eax, eax
    jz   ok
    xor  eax, eax
    jmp  {EPILOG:#x}
ok:
    jmp  {CONT:#x}
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
print("--- create_init fork tolerance (slot 0x9E401F80) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#7: create_init fork tolerance (local guard @0x9E401F80)")
