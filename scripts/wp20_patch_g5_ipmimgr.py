#!/usr/bin/env python3
"""WP20 G5 — THE SceIpmiMgr MODULE-INIT ENOMEM TOLERANCE (the user's plan #5)
          (panic: uma_zcreate(SceIpmiMgrConnectionCB, 2312, ...)=NULL)

CASCADE (after pfsmgr's designed 'contigmalloc failed.' + 'MOD_LOAD
  error 12', the NEXT module's MOD_LOAD panicked):
      module evhand 0x9ebd1da0 (esi=0 = MOD_LOAD):
        eventhandler_register(process_ctor/exit handlers)  [ok]
        call 0x9ebd2070 (the body):
            call 0x9e7897e0("SceIpmiMgr")      [ok]
            malloc(0x48, ..., 0x102)            [ok]
            sx_init("SceIpmiMgrSLSx")           [ok]
            uma_zcreate("SceIpmiMgrConnectionCB", 0x908, ...) -> NULL
            -> PANIC 'uma_zcreate(...)=NULL'
  The body has THREE zcreate NULL->panic blocks (ConnectionCB /
  ConnectRequest / ConnReqBufCtrl) AND NULL->panic blocks for its
  malloc and its subsystem handle — the module is a fail-safe
  consumer that CANNOT run without its zones (the early-boot
  zone_create answers the designed NULL — the WP16/17 semantics KEPT).

THE USER'S FIX (verbatim): "入口返回 error/0" — the evhand ENTRY
  (0x9ebd1da0, which also shields the body 0x9ebd2070):
    esi == 0 (MOD_LOAD)  -> mov eax, 0xc (ENOMEM); plain ret — nothing
                            registered: module_register_init prints
                            'MOD_LOAD (SceIpmiMgr...) error 12' and
                            walks on (the MOD_UNLOAD cleanup call also
                            hits this guard and answers the designed 0);
    esi != 0             -> xor eax, eax; ret (the evhand's OWN design).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E402D00                    # WP20 slot ledger (G3 used 0x9E402B80)
S = 0x9EBD1DA0                       # the evhand entry (8B)
OLD = bytes.fromhex("554889e585f67559")   # push rbp; mov rbp,rsp; test esi,esi; jne +0x59

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

C = """
    test esi, esi
    jne  other_event
    mov  eax, 0xc
    ret
other_event:
    xor  eax, eax
    ret
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

print("--- SceIpmiMgr module-init ENOMEM tolerance (slot 0x9E402D00) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print("OK WP20-G5: SceIpmiMgr ENOMEM tolerance (@0x9EBD1DA0 evhand entry, "
      "body 0x9EBD2070 shielded) — no uma_zcreate panic")
