#!/usr/bin/env python3
"""WP20 G15 — THE MP3 NULL-BUFFER INIT SKIP  [NEW FRONTIER — the last
            budgeted comprehensive patch, 15/15]
          (crash 0xffffffff9e649024 = memset(NULL, 0, 0x2818) — right
           after '[MP3] failed to init message thread')

CASCADE (GDB-caught, this session): SYSINIT walker 0x9e926333 ->
  0x9e975139 -> the module reporting path 0x9e8691b6 -> 0x9e869390 ->
  0x9eaf0be2 -> 0x9ef0b581 -> 0x9ef0b1b8 -> fn 0x9ee02d40:

    0x9ee02d52  eax = 0xffffffea                ; the designed EINVAL
    0x9ee02d57  cmp byte [flag], 1; jne 0x9ee02e9b   ; the designed skip
    0x9ee02d64  rax = [global]
    0x9ee02d79  rax = [rax + 0xa8]
    0x9ee02d80  r14 = [rax + 0x78]              ; the session buffer — NULL
    0x9ee02d84  rdi = r14
    0x9ee02d87  call memset(rdi, 0, 0x2818)     <<< CR2=0x0 (rdi==NULL)
    ...        the whole session init on r14 ...
    0x9ee02e9b  <the designed exit>: canary; add rsp,0xa48; pops; ret

FIX — THE LOCAL GUARD: hook [0x9ee02d80, +5) — the mov r14 + the mov
  rdi's REX byte are replaced by a 5B E9 into the cave:
    mov r14,[rax+0x78] (replay); test r14,r14; jnz live;
    eax = 0xffffffea (the designed error, re-set — rax was clobbered);
    jmp the designed exit 0x9ee02e9b (rcx and the canary are intact).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E403600                    # WP20 slot ledger (G11 twins used 0x9E403500)
S = 0x9EE02D80
CONT = 0xFFFFFFFF9EE02D87            # the memset call
EXIT = 0xFFFFFFFF9EE02E9B            # the designed exit (canary + big epilogue)
OLD = bytes.fromhex("4c8b7078" + "4c")   # mov r14,[rax+0x78]; (REX of mov rdi,r14)

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

C = f"""
    mov  r14, qword ptr [rax + 0x78]
    test r14, r14
    jnz  live
    mov  eax, 0xffffffea
    jmp  {EXIT:#x}
live:
    mov  rdi, r14
    jmp  {CONT:#x}
"""

code = asm(C, SLOT)
assert len(code) <= 0x80
print(f"slot {SLOT:#x}: {len(code):#x}B  hook {S:#x} (5B)")

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

off = S - KTEXT
site = bytes(img[off:off+5])
if site[:1] == b"\xe9":
    rel_expect = SLOT - (S + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    hooked = True
else:
    if site != OLD:
        print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
    hooked = False

off = SLOT - KTEXT
cur = bytes(img[off:off+len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    print(f"FAIL slot {SLOT:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)

img[off:off+len(code)] = code
if not hooked:
    rel = SLOT - (S + 5)
    off = S - KTEXT
    img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

print("--- MP3 NULL-buffer init skip (slot 0x9E403600) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print("OK WP20-G15: MP3 NULL-buffer init skip (@0x9EE02D80 -> slot 0x9E403600, "
      "designed EINVAL exit)")
