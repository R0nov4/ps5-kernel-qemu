#!/usr/bin/env python3
"""WP15 #12 — AP-state loop NULL-object exit guard (crash 0x9ea92621, CR2=0x400 W).

ROOT CAUSE: the caller of the per-CPU init (0x9eaa72b0, guarded by WP15#11)
loops marking per-CPU state and, at loop exit, writes the final state to the
LAST returned object:
    0x9ea925f0  call 0x9eaa72b0              ; next pcpu obj (NULL via gs:[8])
    0x9ea925f5  cmp qword ptr [0xa1e25180], 0 ; the 'more CPUs' gate (== 0)
    0x9ea925fd  je 0x9ea92621                ; exit path
    0x9ea92621  mov dword ptr [rax + 0x400], 4   <<< CRASH (rax==NULL)
  With gs:[8] NULL the function returns 0 and the exit path NULL-writes.

FIX: cave34 @0x9E400A00 replacing [0x9ea925f5, 0x9ea925fd):
    rax == 0 -> the AP state machine has no object to mark -> clean
    function exit (pop rbp; ret) — correct for our single-CPU boot (the
    trampoline never launches the APs, so the loop would never mark any
    real object anyway).
    rax != 0 -> replay the gate (cmp [0xa1e25180], 0 via an absolute
    address — rcx is dead here: overwritten at 0x9ea925ff on the
    fall-through path, unused on the je path) and continue on the
    original paths.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE34  = 0x9E400A00
SITE    = 0x9EA925F5
EXIT_F  = 0xFFFFFFFF9EA92621      # the original je target
LOOP_F  = 0xFFFFFFFF9EA925FF      # the fall-through (mov rcx, [rax+8])
GATE    = 0xFFFFFFFFA1E25180      # the 'more CPUs' global

SITE_OLD = bytes.fromhex("48833d832b3903007422")   # cmp [rip+..],0 ; je (10B)

CAVE34_ASM = f"""
    test rax, rax
    jnz  orig
    pop  rbp
    ret
orig:
    mov  rcx, {GATE:#x}
    cmp  qword ptr [rcx], 0
    je   {EXIT_F:#x}
    jmp  {LOOP_F:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE34_ASM, CAVE34)
if not enc:
    print("ASM FAILED"); sys.exit(1)
cave34 = bytes(enc)
print(f"cave34: {len(cave34):#x}B @ {CAVE34:#x}")
assert len(cave34) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = SITE - KTEXT
if bytes(img[off:off+len(SITE_OLD)]) != SITE_OLD:
    print(f"FAIL site {SITE:#x}: {bytes(img[off:off+len(SITE_OLD)]).hex()}")
    print(f"  expected: {SITE_OLD.hex()}")
    sys.exit(1)
off = CAVE34 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave34 {CAVE34:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

rel = CAVE34 - (SITE + 5)
off = SITE - KTEXT
img[off:off+len(SITE_OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(SITE_OLD) - 5)

off = CAVE34 - KTEXT
img[off:off+len(cave34)] = cave34

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave34 ---")
for i in md.disasm(cave34, CAVE34):
    print(f"  {i.address:#x}  {i.bytes.hex():<20} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP15#12: AP-state loop NULL-object exit guard (cave34 @0x9E400A00)")
