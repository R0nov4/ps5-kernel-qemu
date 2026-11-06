#!/usr/bin/env python3
"""WP18 #24 — the thread-create proc-alloc NULL skip (slot @0x9E402A00)
          (crash 0xffffffff9e92a664, CR2=0x468 — the netisr setup
          callback dereferencing the NULL proc object).

ROOT (GDB wp18_gdb_c10 + the callback's prologue 'r14 = rdi'): the
  generic thread-create F3 0x9ef80a40:
    0x9ef80a4f  rdi = [0xa2171de8]        ; the PROC zone-table — ZERO
    0x9ef80a5d  rax = bucket_alloc(rdi, 0, 2)   <- NULL
    0x9ef80a62  rdi = rax; rbx = rax      ; the NULL 'object'
    0x9ef80a6b  call 0x9e92a540(rdi)      ; the setup callback:
        r14 = rdi = NULL ...
        0x9e92a664  mov [r14+0x468], r12  <<< CR2 = 0x468 WRITE
    ... the callback's other r14 writes ([+0x470], [+0x478]) ...
  The callback (and F3's own error-cleanup calls 0x9ee40f70(rbx)/
  0x9ee93190(rbx+0x90)) all walk the never-allocated object.

FIX — the LOCAL GUARD at F3's proc-alloc call [0x9ef80a5d, 0x9ef80a62)
  (5B 'call 0x9e82b880'):
    rax == 0  -> xor ebx,ebx; jmp F3's own exit 0x9ef80aa0 ('mov rax,rbx;
                 pop rbx; pop r14; pop rbp; ret' — returns NULL, the
                 designed 'no thread' answer; the callback AND the
                 cleanup calls are all skipped);
    rax != 0  -> jmp 0x9ef80a62 (the designed callback flow).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E402A00
S = 0x9EF80A5D                       # call 0x9e82b880 (5B)
BUCKET = 0xFFFFFFFF9E82B880
CONT = 0xFFFFFFFF9EF80A62            # mov rdi,rax (the designed path)
EXIT = 0xFFFFFFFF9EF80AA0            # mov rax,rbx; pop rbx; pop r14; pop rbp; ret

OLD = bytes.fromhex("e81eae8aff")    # call 0x9e82b880

C = f"""
    call {BUCKET:#x}
    test rax, rax
    jz   alloc_failed
    jmp  {CONT:#x}
alloc_failed:
    xor  ebx, ebx
    jmp  {EXIT:#x}
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
print("--- thread-create proc-alloc NULL skip (slot 0x9E402A00) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#24: thread-create proc-alloc NULL skip (local guard @0x9E402A00)")
