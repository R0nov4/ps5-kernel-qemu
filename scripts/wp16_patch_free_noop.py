#!/usr/bin/env python3
"""WP16 #11 — free() no-op for bump-window objects
         (panic: free: address 0xffff8e773f1a3fd0(0xffff8e773f1a0000) has not been allocated).

ROOT CAUSE:
  The malloc bump (cave50) hands out objects from the DMAP window
  [0x3F1A1000, 0x3F200000) — the boot now reaches the sysctl-leaf
  registration + 'Preloaded elf kernel "kernel" at 0xffffffffa2224000.'
  stages, and some temporary allocation gets FREED -> the free()
  validation walks the zone/slab metadata -> the bump object has none
  -> 'free: address ... has not been allocated' panic.

FIX — cave51 @0x9E401280 replacing [0x9eff8efa, 0x9eff8eff) (the
  free-panic block head, 'call 0x9ebe1950', 5B):
    - the freed address (r15 — the printf's first %p) inside the bump
      window [0xffff8e773f1a1000, 0xffff8e773f200000):
      silent no-op free — replicate the designed free epilogue exactly
      (add rsp,8; pop rbx/r12/r13/r14/r15/rbp; tail-jmp 0x9ea92650).
      The bump memory 'leaks' — harmless for a boot progression kernel.
    - anything else: replay 'call 0x9ebe1950' and continue 0x9eff8eff
      (the designed panic path — real double-free detection stays).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE51 = 0x9E401280
S51, S51E = 0x9EFF8EFA, 0x9EFF8EFF          # 'call 0x9ebe1950' (5B)
WIN_LO = 0xFFFF8E773F1A1000
WIN_HI = 0xFFFF8E773F200000

OLD51 = bytes.fromhex("e8518abeff")         # call 0xffffffff9ebe1950

C51 = f"""
    movabs r10, {WIN_LO:#x}
    cmp  r15, r10
    jb   real_panic
    movabs r10, {WIN_HI:#x}
    cmp  r15, r10
    jae  real_panic
    add  rsp, 8
    pop  rbx
    pop  r12
    pop  r13
    pop  r14
    pop  r15
    pop  rbp
    jmp  {0xFFFFFFFF9EA92650:#x}
real_panic:
    call {0xFFFFFFFF9EBE1950:#x}
    jmp  {0xFFFFFFFF9EFF8EFF:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C51, CAVE51)
print(f"cave51: {len(code):#x}B @ {CAVE51:#x}  hook {S51:#x} ({len(OLD51)}B)")
assert len(code) <= 0x80, "cave51 too big"

img = bytearray(open(IMG, "rb").read())

off = S51 - KTEXT
site = bytes(img[off:off+len(OLD51)])
if site[:1] == b"\xe9":
    rel_expect = CAVE51 - (S51 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S51:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S51:#x}: already hooked to cave51 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD51:
        print(f"FAIL site {S51:#x}: {site.hex()} (expected {OLD51.hex()})"); sys.exit(1)
    hooked = False

off = CAVE51 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave {CAVE51:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

md = Cs(CS_ARCH_X86, CS_MODE_64)
insns = list(md.disasm(code, CAVE51))
blob = code.hex()
if "49ba00101a3f778effff" not in blob:
    for i in insns:
        print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
    print("FAIL: window movabs not found"); sys.exit(1)

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE51 - (S51 + 5)
    off = S51 - KTEXT
    img[off:off+len(OLD51)] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

print("--- cave51 ---")
for i in insns:
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP16#11: free() no-op for bump objects (cave51)")
