#!/usr/bin/env python3
"""WP18 #9 — the idle_setup FIRST kproc tolerance (slot @0x9E402080)
          (panic 'idle_setup: kproc_create error 12' — the FIRST create).

The idle_setup fn has TWO kproc-family create calls (both 'call
  0x9ed162d0', both with the 0x20-byte arg stack: sub rsp,8 + 3 pushes):
  - 0x9efa4bac  the FIRST create (the main idleproc) — its error path
                'jne 0x9efa4d7a' -> the panic block w/ the string @
                0x9efa4d90 ('idle_setup: kproc_create error %d')  <<< THIS PANIC
    0x9efa4bb5  mov rdi,[rbp-0x48]           ; the created-proc out-param
    0x9efa4bb9  mov [r13+8], rdi
    0x9efa4bbd  test eax, eax
    0x9efa4bbf  jne 0x9efa4d7a
    0x9efa4bc5  ... the success body (flags, priorities, the domain loop)
  - 0x9efa4ca5  the per-domain loop create (already guarded by WP18#8).

FIX — the LOCAL GUARD (the same pattern as WP18#8): hook the FIRST call
  [0x9efa4bac, 0x9efa4bb1) (5B):
    replay the call; eax != 0 -> tolerate: xor eax,eax; 'add rsp,0x20'
    (restore the frame level) -> jmp the loop-exit canary 0x9efa4d5b
    (the epilogue runs; the whole idle-setup body incl. the [r13+8]
    store and the domain loop is skipped).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E402080                    # the old cave77 slot, freed by the rollback
S = 0x9EFA4BAC                       # call 0x9ed162d0 (5B)
KPROC = 0xFFFFFFFF9ED162D0
CONT = 0xFFFFFFFF9EFA4BB1            # add rsp,0x20 (the designed path)
CANARY = 0xFFFFFFFF9EFA4D5B          # the loop-exit canary check

OLD = bytes.fromhex("e81f17d7ff")    # call 0x9ed162d0

C = f"""
    call {KPROC:#x}
    test eax, eax
    jz   ok
    xor  eax, eax
    add  rsp, 0x20
    jmp  {CANARY:#x}
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
print(f"slot 0x{SLOT:x}: {len(code):#x}B  hook {S:#x} (5B)")
assert len(code) <= 0x80

img = bytearray(open(IMG, "rb").read())

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
print("--- idle_setup FIRST kproc tolerance (slot 0x9E402080) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#9: idle_setup FIRST kproc tolerance (local guard @0x9E402080)")
