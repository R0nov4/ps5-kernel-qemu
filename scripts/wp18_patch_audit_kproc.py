#!/usr/bin/env python3
"""WP18 #6 — the audit_worker kproc tolerance (slot @0x9E401F00)
          (panic 'audit_worker_init: kproc_create returned 12').

CASCADE: WP18#5 made fork's zone-alloc failure return the designed ENOMEM
  (0xc) -> kproc_create propagates 12 -> audit_worker_init's designed
  panic at 0x9e67fd52 ('audit_worker_init: kproc_create returned %d').
  The audit worker is a non-essential daemon (audit record drain); with
  the kthread machinery unable to create processes on this boot the
  designed demand-panic halts the SYSINIT march.

FIX — the LOCAL GUARD (the WP13 'non-essential subsystem' skip pattern):
  hook the kproc_create call [0x9e67fd2c, 0x9e67fd31) (5B 'call
  0x9ed155b0'):
    replay the call in the cave;
    eax == 0  -> jmp 0x9e67fd31 (the designed success test/exit);
    eax != 0  -> tolerate: xor eax,eax; jmp the fn's own success exit
                 0x9e67fd35 ('add rsp,8; pop rbx; pop rbp; ret' — the
                 3-push frame is balanced at the hook point) — the
                 panic path (0x9e67fd3c..) is skipped entirely.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E401F00                    # the old cave74 slot, freed by the rollback
S = 0x9E67FD2C                       # call 0x9ed155b0 (5B)
KPROC = 0xFFFFFFFF9ED155B0           # kproc_create
CONT = 0xFFFFFFFF9E67FD31            # test eax,eax (the designed path)
EXIT = 0xFFFFFFFF9E67FD35            # add rsp,8; pop rbx; pop rbp; ret

OLD = bytes.fromhex("e87f586900")    # call 0x9ed155b0

C = f"""
    call {KPROC:#x}
    test eax, eax
    jz   ok
    xor  eax, eax
    jmp  {EXIT:#x}
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
print("--- audit_worker kproc tolerance (slot 0x9E401F00) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#6: audit_worker kproc tolerance (local guard @0x9E401F00)")
