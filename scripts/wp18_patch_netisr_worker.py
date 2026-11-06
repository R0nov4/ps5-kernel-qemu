#!/usr/bin/env python3
"""WP18 #23 — the netisr worker-init NULL-object skip (slot @0x9E402980)
          (crash 0xffffffff9e851681, CR2=0x68 WRITE — the netisr worker
          registration; serial: 'netisr_init: forcing maxthreads...').

CASCADE (GDB wp18_gdb_c10): the netisr thread creation ->
  the generic thread-create 0x9ef80a40 -> the setup callback 0x9e92a540
  -> the worker alloc 0x9e851ac0:
    rax = bucket_alloc([0xa190e0c0], 0, 2)   ; the netisr worker ZONE —
                                              ; ZERO (its zone_create
                                              ; failed earlier) -> NULL
    rdx = rax (NULL); call 0x9e851670        ; worker-init
    0x9e851681  mov [rdx+0x68], 0            <<< CR2 = 0x68 WRITE
  The init fn writes a dozen fields of the never-allocated worker.

FIX — the LOCAL GUARD at the init fn's entry: hook [0x9e851670,
  0x9e851676) (6B: 'push rbp; mov rbp,rsp; push r15'):
    rdx == 0  -> xor eax,eax; plain ret (nothing pushed — a complete
                 no-op: no worker object -> nothing to register; the
                 caller ignores the return value — it keeps its own
                 r13 = the alloc result);
    rdx != 0  -> replay the 3 prologue pushes -> 0x9e851676.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E402980
S = 0x9E851670                       # push rbp; mov rbp,rsp; push r15 (6B)
CONT = 0xFFFFFFFF9E851676            # push r14 (the designed prologue tail)

OLD = bytes.fromhex("554889e54157")

C = f"""
    test rdx, rdx
    jz   noworker
    push rbp
    mov  rbp, rsp
    push r15
    jmp  {CONT:#x}
noworker:
    xor  eax, eax
    ret
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
print("--- netisr worker-init NULL-object skip (slot 0x9E402980) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#23: netisr worker-init NULL-object skip (local guard @0x9E402980)")
