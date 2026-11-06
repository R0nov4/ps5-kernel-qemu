#!/usr/bin/env python3
"""WP18 #20 — the intr-event log NULL-buffer skip (slot @0x9E402800)
          (crash 0xffffffff9e8b78df, CR2=0x0 — the kern_intr.c event
          publish path; GDB wp18_gdb_c7).

CASCADE (GDB): the intr-event setup continuation:
    0x9eb70124  call 0x9eb6f670        ; the event bind (fails quietly)
    0x9eb7012d  test eax,eax ; jne -> 'mov r15d,eax; jmp 0x9eb70179'
                                       ; the DESIGNED error path JUMPS
                                       ; STRAIGHT TO the canary/epilogue,
                                       ; skipping the whole publish tail
    0x9eb7014f  xor r15d,r15d          ; the success value
    0x9eb70154  mov rbx,[rax+8]        ; the NAME BUFFER — NULL (the fresh
                                       ; bump-page event; WP18#19's family)
    0x9eb70158  mov rdi,rbx
    0x9eb7015b  call 0x9e8b78b0        ; log(buf, 0, 'kern_intr.c', 0x475)
                                       ;   -> 'mov rdi,[rdi]' <<< CR2=0
    0x9eb70160  or byte [rbx+0x384],0x10   ; would fault at 0x384 next
    0x9eb70167  ... the [rbx]-mutex unlock ...
    0x9eb70179  the canary check + epilogue (the designed skip target)

FIX — the LOCAL GUARD: hook [0x9eb70154, 0x9eb70167) (19B — all four
  displaced instructions replayed):
    [rax+8] == 0  -> the no-name publish: jmp 0x9eb70179 (the SAME
                     canary/epilogue target the designed error path
                     takes — the log, the flags-OR and the [rbx]-unlock
                     are all skipped by design precedent; r15d = 0 = the
                     success return);
    else          -> replay 'mov rbx,[rax+8]; mov rdi,rbx; call log; or
                     byte [rbx+0x384],0x10' -> 0x9eb70167.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E402800
S = 0x9EB70154                       # mov rbx,[rax+8] .. or byte [rbx+0x384],0x10 (19B)
CONT = 0xFFFFFFFF9EB70167            # xor esi,esi (the unlock prep)
SKIP = 0xFFFFFFFF9EB70179            # the canary/epilogue (the designed error-path target)
LOG = 0xFFFFFFFF9E8B78B0

OLD = bytes.fromhex("488b58084889dfe85077d4ff808b8403000010")

C = f"""
    mov  rbx, qword ptr [rax + 8]
    test rbx, rbx
    jz   nullbuf
    mov  rdi, rbx
    call {LOG:#x}
    or   byte ptr [rbx + 0x384], 0x10
    jmp  {CONT:#x}
nullbuf:
    jmp  {SKIP:#x}
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
print("--- intr-event log NULL-buffer skip (slot 0x9E402800) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#20: intr-event log NULL-buffer skip (local guard @0x9E402800)")
