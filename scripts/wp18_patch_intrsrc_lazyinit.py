#!/usr/bin/env python3
"""WP18 #17 — the intr-source registry lazy-init guard (slot @0x9E402680)
          (crash 0xffffffff9eb6f11a, CR2=0x0 WRITE — the ioapic/lapic
          configuration SYSINIT, the interrupt-source registration).

THE BOOT STAGE (serial): 'ioapic0: intpin 11 trigger: level' /
  'lapic: Routing NMI -> LINT1' / 'ioapic0 <Version 2.0> irqs 0-23' —
  the kernel is registering the ioapic/lapic interrupt sources.

CRASH: the registry's singly-linked APPEND:
    0x9eb6f0ff  rax = [0xa05f8288]     ; the current tail (the registry
                                       ; head global — wiped to 0 at boot
                                       ; by WP12#7's relocation)
    0x9eb6f109  mov [r15], 0           ; new->next = NULL
    0x9eb6f11a  mov [rax], r15         ; tail->next = new   <<< CR2=0 (the
                                       ; FIRST registration: tail=NULL!)
    0x9eb6f11d  mov [0xa05f8288], r15  ; the registry := the new tail
    0x9eb6f124  call mtx_unlock
  The live dump's registry held a real tail (residue); on this cold boot
  the FIRST append writes [NULL]. After this one guard the chain links
  naturally (the global becomes non-NULL).

FIX — the LOCAL GUARD (the WP15 TAILQ-lazy-init pattern): hook
  [0x9eb6f11a, 0x9eb6f124) (11B: 'mov [rax],r15' (4B) + the rip-relative
  'mov [0xa05f8288],r15' (7B)):
    rax == 0  -> skip ONLY the [rax] link; the global store still runs
                 (replayed via movabs — the list starts at r15);
    rax != 0  -> replay both stores verbatim -> 0x9eb6f124.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E402680
S = 0x9EB6F11A                       # mov [rax],r15; mov [0xa05f8288],r15 (11B)
CONT = 0xFFFFFFFF9EB6F124            # call mtx_unlock
REG = 0xFFFFFFFFA05F8288             # the intr-source registry head/tail

OLD = bytes.fromhex("4c89384c893d6491a801")

C = f"""
    test rax, rax
    jz   empty_list
    mov  qword ptr [rax], r15
    movabs r10, {REG:#x}
    mov  qword ptr [r10], r15
    jmp  {CONT:#x}
empty_list:
    movabs r10, {REG:#x}
    mov  qword ptr [r10], r15
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
print("--- intr-source registry lazy-init guard (slot 0x9E402680) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#17: intr-source registry lazy-init guard (local guard @0x9E402680)")
