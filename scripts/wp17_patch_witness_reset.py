#!/usr/bin/env python3
"""WP17 #16 — the witness-reset reseed (cave76 @0x9E402000).

ROOT CAUSE (GDB wp17_gdb_c21 — the watchpoint):
  The image seed of [thread0+0x78] (WP17#15) gets WIPED at runtime by
  the witness-subsystem reset fn:
    0x9e81d11e  call mtx_init(0xa18e6db8, name, 0, 1)
    0x9e81d123  mov [thread0+0x128], 0
    0x9e81d12e  mov [thread0+0x78], 0        ; <<< THE WIPE (rip=0x9e81d139)
  On the designed boot this reset runs BEFORE the per-thread witness
  objects are allocated (the later allocation refills +0x78 with a real
  object); on this boot the allocation never runs -> NULL ->
  'mov rax,[rdi]' with rdi=0x18 -> CR2=0x18 (WP17#15's crash).

FIX — hook the wipe instruction [0x9e81d12e, 0x9e81d139) (11B
  'mov qword [thread0+0x78], 0'): the cave writes the SEED
  (DMAP(0x3F1A0A00) — the pristine-zero witness page) instead of NULL,
  then jumps the designed continuation 0x9e81d139 ('add rsp,8' + the
  epilogue). The reset keeps its 'fresh empty witness' semantics — the
  empty list at the zero page.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE76 = 0x9E402000
S76, S76E = 0x9E81D12E, 0x9E81D139          # mov [thread0+0x78], 0 (11B)
CONT76 = 0xFFFFFFFF9E81D139                  # 'add rsp,8' + epilogue

TD0_WITNESS = 0xFFFFFFFFA19788D8
SEED_WITNESS = 0xFFFF8E773F1A0A00

OLD76 = bytes.fromhex("48c7059fb7150300000000")   # mov [rip+0x315b79f], 0

C76 = f"""
    movabs rax, {TD0_WITNESS:#x}
    movabs rcx, {SEED_WITNESS:#x}
    mov  qword ptr [rax], rcx
    jmp  {CONT76:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C76, CAVE76)
print(f"cave76: {len(code):#x}B @ {CAVE76:#x}  hook {S76:#x} (11B)")
assert len(code) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = S76 - KTEXT
site = bytes(img[off:off+len(OLD76)])
if site[:1] == b"\xe9":
    rel_expect = CAVE76 - (S76 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S76:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S76:#x}: already hooked to cave76 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD76:
        print(f"FAIL site {S76:#x}: {site.hex()} != {OLD76.hex()}"); sys.exit(1)
    hooked = False

off = CAVE76 - KTEXT
cur = bytes(img[off:off+len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    img[off:off+0x80] = b"\xcc" * 0x80
    print(f"cave {CAVE76:#x}: stale body — blanking for rewrite")
print("site + cave assertions OK")

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE76 - (S76 + 5)
    off = S76 - KTEXT
    img[off:off+len(OLD76)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD76) - 5)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave76 (witness-reset reseed) ---")
for i in md.disasm(code, CAVE76):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP17#16: witness-reset reseed (cave76)")
