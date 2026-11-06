#!/usr/bin/env python3
"""WP18 #8 — the idle_setup kproc tolerance (slot @0x9E402000)
          (panic 'idle_setup: kproc_create error 12').

CASCADE: fork's designed ENOMEM -> the idle-domain loop's kproc-family
  create (0x9ed162d0) fails -> the designed panic at 0x9efa4d90/
  0x9efa4db4 ('idle_setup: kproc_create error %d').

  The loop (per CPU domain):
    0x9efa4c70  sub rsp, 8
    0x9efa4c91  push r10            ; 3 arg pushes = 0x20 total
    0x9efa4c9a  push r10
    0x9efa4ca3  push r10
    0x9efa4ca5  call 0x9ed162d0     ; the kproc-family create
    0x9efa4cae  test eax, eax
    0x9efa4cb0  jne 0x9efa4d9e      ; -> the panic block
    0x9efa4cb6  ... the success body ...
    0x9efa4d4e  mov r14,[r14+0x38]  ; the next domain
    0x9efa4d55  jne 0x9efa4c60      ; loop
    0x9efa4d5b  the canary check
    0x9efa4d6b  add rsp,0x28; pop rbx; pop r12; pop r13; pop r14; pop r15; pop rbp; ret

FIX — the LOCAL GUARD: hook the create call [0x9efa4ca5, 0x9efa4caa)
  (5B 'call 0x9ed162d0'):
    replay the call in the cave;
    eax == 0  -> jmp 0x9efa4cae (the designed success body);
    eax != 0  -> tolerate: xor eax,eax; 'add rsp,0x20' (discard the 3
                 pushed args + the sub-8 slot — restoring the frame to
                 the level the epilogue expects) -> jmp the loop-exit
                 canary 0x9efa4d5b (the epilogue runs; the remaining
                 idle procs are skipped — no idle threads exist on this
                 boot anyway).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E402000                    # the old cave76 slot, freed by the rollback
S = 0x9EFA4CA5                       # call 0x9ed162d0 (5B)
KPROC = 0xFFFFFFFF9ED162D0
CONT = 0xFFFFFFFF9EFA4CAE            # test eax,eax
CANARY = 0xFFFFFFFF9EFA4D5B          # the loop-exit canary check

OLD = bytes.fromhex("e82616d7ff")    # call 0x9ed162d0

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
print("--- idle_setup kproc tolerance (slot 0x9E402000) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#8: idle_setup kproc tolerance (local guard @0x9E402000)")
