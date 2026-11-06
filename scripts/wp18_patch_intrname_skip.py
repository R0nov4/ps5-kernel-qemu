#!/usr/bin/env python3
"""WP18 #19 — the intr-event naming NULL-buffer skip (slot @0x9E402780)
          (crash 0xffffffff9ed47b89, CR2=0x294 WRITE — the ioapic/lapic
          interrupt-event NAMING flow).

CASCADE (GDB wp18_gdb_c6): the ioapic setup fn calls the event-naming
  helper 0x9eb6fa70(rdi = the fresh event wrapper):
    0x9eb6fa77  rsi = [rdi]          ; the source struct (valid)
    0x9eb6fa7a  rbx = [rdi+8]        ; the NAME BUFFER — NULL on this boot
                                      ; (the wrapper is a fresh bump page;
                                      ; the designed buffer alloc never ran)
    0x9eb6fa93  lea rdi, [rbx+0x294] ; dst = NULL+0x294 = 0x294
    0x9eb6faa3  call strlcpy(0x9ed47b70)  ; 'mov [rdi+rcx],sil' <<< CR2=0x294
  The fn then continues using rbx throughout (the publish/log/priority
  calls) — the whole naming/publish pass needs the buffer.

FIX — the LOCAL GUARD (the WP13 non-essential-skip pattern): hook the
  fn entry [0x9eb6fa70, 0x9eb6fa76) (6B: 'push rbp; mov rbp,rsp;
  push r14'):
    [rdi+8] == 0  -> plain ret (nothing pushed yet — a complete no-op:
                     the event keeps no name on this boot);
    else          -> replay the 3 prologue pushes -> 0x9eb6fa76 ('push
                     rbx' — the designed prologue tail; rbx is reloaded
                     from [rdi+8] by the designed flow anyway).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E402780
S = 0x9EB6FA70                       # push rbp; mov rbp,rsp; push r14 (6B)
CONT = 0xFFFFFFFF9EB6FA76            # push rbx (the prologue tail)

OLD = bytes.fromhex("554889e54156")

C = f"""
    mov  rbx, qword ptr [rdi + 8]
    test rbx, rbx
    jz   nullbuf
    push rbp
    mov  rbp, rsp
    push r14
    jmp  {CONT:#x}
nullbuf:
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
print("--- intr-event naming NULL-buffer skip (slot 0x9E402780) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#19: intr-event naming NULL-buffer skip (local guard @0x9E402780)")
