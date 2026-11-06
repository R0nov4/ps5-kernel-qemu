#!/usr/bin/env python3
"""WP18 #18 — the intr-ithread kproc tolerance (slot @0x9E402700)
          (panic 'kproc_create() failed with 12' — the ioapic/lapic
          interrupt-thread creation during the ICU SYSINIT).

CRASH STAGE (serial): 'ioapic0: ver 0x20 maxredir 0x17' / 'Routing
  external 8259A's -> intpin 0' / intpin trigger messages — the icu/ioapic
  setup creating its interrupt threads.

The SWI/ithread creator fn:
    0x9eb6f964  sub rsp, 8                 ; the arg stack (0x20 total)
    0x9eb6f968  ... 3 pushes ...
    0x9eb6f9a3  call 0x9ed162d0            ; the kproc-family create
    0x9eb6f9a8  add rsp, 0x20
    0x9eb6f9ac  test eax, eax
    0x9eb6f9ae  jne 0x9eb6fa35             ; -> panic 'kproc_create() failed with %d'
    0x9eb6f9b4  ... the success body (the event's flags/links) ...
    0x9eb6fa27  mov rax,rbx; add rsp,0x18; pop rbx; pop r14; pop r15; pop rbp; ret
  (rbx = the intr-event object, allocated earlier in the fn.)

FIX — the LOCAL GUARD (the WP18 kproc-tolerance pattern): hook the
  create call [0x9eb6f9a3, 0x9eb6f9a8) (5B):
    eax == 0  -> jmp 0x9eb6f9a8 (the designed success body);
    eax != 0  -> tolerate: xor eax,eax; 'add rsp,0x20' (discard the arg
                 stack, restoring the frame level the epilogue expects)
                 -> jmp the success exit 0x9eb6fa27 (returns the event
                 object; the panic block is skipped; the ithread just
                 does not exist on this boot).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E402700
S = 0x9EB6F9A3                       # call 0x9ed162d0 (5B)
KPROC = 0xFFFFFFFF9ED162D0
CONT = 0xFFFFFFFF9EB6F9A8            # add rsp,0x20 (the designed path)
EXIT = 0xFFFFFFFF9EB6FA27            # mov rax,rbx; add rsp,0x18; pops; ret

OLD = bytes.fromhex("e828691a00")    # call 0x9ed162d0

C = f"""
    call {KPROC:#x}
    test eax, eax
    jz   ok
    xor  eax, eax
    add  rsp, 0x20
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
    img[off:off+len(OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- intr-ithread kproc tolerance (slot 0x9E402700) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#18: intr-ithread kproc tolerance (local guard @0x9E402700)")
