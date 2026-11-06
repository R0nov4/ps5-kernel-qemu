#!/usr/bin/env python3
"""WP22 G38 — THE GBASE-MODULE DESIGNED LOAD-FAILURE

FRONTIER (G37 boot): the march passes pltauth/sdma/gbase-map error prints
and dies in the module's own NULL-deref minefield (every failed
allocation's result is immediately dereferenced: [rax]=0 with rax=NULL @
0x9eed45fe, then [rcx+0x60] with the failed map-create results, ...).

The function 0x9eed4320 IS the module's modevent handler:
    cmp esi, 1  ; je  0x9eed4781   (MOD_UNLOAD)
    test esi,esi; jne 0x9eed4861   (MOD_SHUTDOWN/QUIESCE)
    <esi==0 = MOD_LOAD: the whole gbase/sdma init>

FIX — THE DESIGNED MODULE-LOAD FAILURE (the exact tolerance this very
boot already exercises for pcist / sm_service / sbl_sm_service):
'MOD_LOAD (gbase...) error 12' — hook the entry, answer error 12
(ENOMEM) immediately. The module framework prints the error and the
march continues; the module's sysctl/map state simply never loads.
Slot 0x9E404580, stub = 'mov eax, 0xc; ret' (6 bytes).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"

S = 0x9EED4320
OLD = bytes.fromhex("554889e541")       # push rbp; mov rbp,rsp; +1st byte of push r15
SLOT = 0x9E404580

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

C = """
    mov    eax, 0xc
    ret
"""
code = asm(C, SLOT)
assert len(code) <= 0x20

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

off = S - KTEXT
site = bytes(img[off:off + 5])
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
cur = bytes(img[off:off + len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    print(f"FAIL slot {SLOT:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)

img[off:off + len(code)] = code
if not hooked:
    off = S - KTEXT
    img[off:off + 5] = b"\xe9" + rel_expect

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP22-G38: gbase-module handler @0x{S:X} -> designed error-12 "
      f"(slot 0x{SLOT:X}, stub {len(code):#x}B) — 'MOD_LOAD error 12' tolerance")
