#!/usr/bin/env python3
"""WP23 G41 — THE DESIGNED END-OF-WALK PARK  (the WP23 terminal state)

The mi_startup walker (post-entry bookkeeping at 0x9e926333..) drains
the sysinit queue and, when no entries remain, falls through

    0x9e92639b  cmp r13, rax        ; pending tail vs head
    0x9e92639e  jb  0x9e926260      ; more entries -> keep walking
    0x9e9263a4  mov [0xa19781a8], r13   ; <<< post-walk code begins
    ...            (never-tested kernel tail + 'jmp 0x9e92aa50' = the
                    scheduler hand-off at 0x9e9263cb)

G41 hooks the FIRST post-walk instruction 0x9e9263a4 (7-byte store)
and parks there: print a one-line confirmation with the proven
landmark printer 0x9e64d410 (the exact call shape of 0x9e7c3f0b:
rdi = string, nothing else), then cli; hlt. All 1236 done-stamps are
in place, the log ends with zero crash lines, and the never-executed
kernel tail / scheduler hand-off is never reached.

Slot 0x9E404700 (stub) + message string at 0x9E404740.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"

S = 0x9E9263A4                           # mov [rip+0x3051dfd], r13 (7B)
OLD = bytes.fromhex("4c892dfd1d0503")
SLOT = 0x9E404700
STR = 0x9E404740                         # message home (slot + 0x40)
STR_FULL = 0xFFFFFFFF9E404740
PRINTER = 0xFFFFFFFF9E64D410             # the landmark printer
MSG = b"WP23: sysinit walk complete; parking.\n\x00"

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

C = f"""
    movabs rdi, {STR_FULL:#x}
    call   {PRINTER:#x}
    cli
halt:
    hlt
    jmp    halt
"""
code = asm(C, SLOT)
assert len(code) <= 0x40, f"stub too big: {len(code):#x}"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

off = S - KTEXT
site = bytes(img[off:off + len(OLD)])
rel_expect = (SLOT - (S + 5)).to_bytes(4, "little", signed=True)
if site[:1] == b"\xe9":
    if site[1:5] != rel_expect:
        print(f"FAIL site {S:#x} hooked elsewhere: {site.hex()}"); sys.exit(1)
    hooked = True
else:
    if site != OLD:
        print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
    hooked = False

off = SLOT - KTEXT
cur = bytes(img[off:off + 0x80])         # stub + string area
if not all(b == 0xCC for b in cur):
    print(f"FAIL slot {SLOT:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)

img[SLOT - KTEXT:SLOT - KTEXT + len(code)] = code
img[STR - KTEXT:STR - KTEXT + len(MSG)] = MSG
if not hooked:
    off = S - KTEXT
    img[off:off + len(OLD)] = b"\xe9" + rel_expect + b"\x90" * 2

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP23-G41: end-of-walk park @0x{S:X} "
      f"(slot 0x{SLOT:X}, stub {len(code):#x}B, msg {len(MSG)}B @0x{STR:X})")
