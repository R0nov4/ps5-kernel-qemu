#!/usr/bin/env python3
"""WP18 #5 — the fork zone-alloc NULL error return (slot @0x9E401E80)
          (crash 0xffffffff9f0a162b, CR2=0x10 READ; the fork1 path).

CASCADE (GDB wp18_gdb_c3): the post-APIC SYSINIT kthread creation ->
  0x9e67fd31 -> fork1-family caller 0x9ed15633 -> fn 0x9f0a1430 (the
  fork internals; strings 'fork'/'maxproc limit exceeded...'):
    0x9f0a1618  rdi = [0xa1979e30]          ; the proc-zone table — ZERO
                                             ; on this boot
    0x9f0a1626  rax = bucket_alloc(rdi, 0, 2)   <- NULL
    0x9f0a162b  r15 = [rax + 0x10]              <<< CR2 = 0x10 READ
  The fn's own error protocol: r14d = the error code; the shared exit
  0x9f0a1461 (canary + 'add rsp,0x38; pop rbx; pop r12; pop r13; pop
  r14; pop r15; pop rbp; ret') returns eax = r14d; the immediate caller
  0x9ed15638 does 'test eax,eax; jne 0x9ed15840' — the designed error
  branch. The fn itself uses error 0xc (ENOMEM) for its alloc-fail path.

FIX — the LOCAL GUARD: hook the bucket_alloc call [0x9f0a1626,
  0x9f0a162b) (5B 'call 0x9e82b880'):
    replay the call in the cave;
    rax == 0  -> the designed ENOMEM error return: eax := 0xc; replicate
                 the fn's own epilogue (the 6-push + sub-0x38 frame is
                 intact at the hook point; the canary check is skipped —
                 nothing corrupted it);
    rax != 0  -> jmp 0x9f0a162b (the designed item deref).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E401E80                    # the old cave73 slot, freed by the rollback
S = 0x9F0A1626                       # call 0x9e82b880 (5B)
BUCKET = 0xFFFFFFFF9E82B880
CONT = 0xFFFFFFFF9F0A162B            # mov r15,[rax+0x10]

OLD = bytes.fromhex("e855a278ff")    # call 0x9e82b880

C = f"""
    call {BUCKET:#x}
    test rax, rax
    jnz  alloc_ok
    mov  eax, 0xc
    add  rsp, 0x38
    pop  rbx
    pop  r12
    pop  r13
    pop  r14
    pop  r15
    pop  rbp
    ret
alloc_ok:
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
print("--- fork zone-alloc NULL error return (slot 0x9E401E80) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#5: fork zone-alloc NULL error return (local guard @0x9E401E80)")
