#!/usr/bin/env python3
"""WP18 #22 — the thread_free NULL-proc skip (slot @0x9E402900)
          (crash 0xffffffff9ef80a01, CR2=0x5cc — the kthread teardown).

CASCADE (GDB wp18_gdb_c9): the SceTaskQ SYSINIT ('SceTaskQ: %s') ->
  kthread_add (0x9ed15ad0) -> thread-create 0x9ef80a40 -> F2 0x9ef808a0
  (the alloc/setup; fails — the proc-zone [0xa2171de8] is zero) -> the
  unwind frees the half-created thread via thread_free F1 0x9ef809a0:
    [thread+0x60] release; cpu_thread_clean (WP18#21-guarded);
    r14 = [thread+8]               ; the PROC — NULL (the fake thread)
    0x9ef80a01  r15d = [r14+0x5cc] ; <<< CR2=0x5cc
    zone_free(NULL proc-zone, thread); the proc tail-call (r14, r15d)
  Every step of the teardown walks the missing PROC.

FIX — the LOCAL GUARD at F1's entry: hook [0x9ef809a0, 0x9ef809a6) (6B:
  'push rbp; mov rbp,rsp; push r15'):
    [rdi+8] == 0  -> plain ret (nothing pushed — a complete no-op: a
                     proc-less fake thread has nothing to tear down);
    else          -> replay the 3 prologue pushes -> 0x9ef809a6 ('push
                     r14' — the designed prologue continues; everything
                     is re-derived from rdi downstream).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E402900
S = 0x9EF809A0                       # push rbp; mov rbp,rsp; push r15 (6B)
CONT = 0xFFFFFFFF9EF809A6            # push r14 (the designed prologue tail)

OLD = bytes.fromhex("554889e54157")

C = f"""
    mov  rax, qword ptr [rdi + 8]
    test rax, rax
    jz   fakethread
    push rbp
    mov  rbp, rsp
    push r15
    jmp  {CONT:#x}
fakethread:
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
print("--- thread_free NULL-proc skip (slot 0x9E402900) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#22: thread_free NULL-proc skip (local guard @0x9E402900)")
