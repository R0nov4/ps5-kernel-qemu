#!/usr/bin/env python3
"""WP15 #18 — idle-loop NULL-proc guard (crash 0x9e642254, CR2=0xb50).

ROOT CAUSE: the kernel main/idle path (0x9e642xxx — the region that
called pmap-activate at 0x9e64221e) spins on the thread's sentinel then
checks the proc object:
    0x9e64224f  mov rcx, [r12 + 8]         ; thread->proc-ish (NULL at runtime!)
    0x9e642254  cmp qword ptr [rcx + 0xb50], 0   <<< CRASH (rcx==0)
    0x9e64225c  jne 0x9e6425a5
    0x9e642262  xor eax, eax ; ...
  thread0's +8 was 0xa1978ef8 in the image (not DMAP, not wiped) but is
  NULL at this point at runtime (one of the early boot paths re-zeroed
  it before the proc was (re)attached).

FIX: cave39 @0x9E400C80 replacing [0x9e64224f, 0x9e642262) (19B):
    rcx == 0 -> the designed 'check == 0' fall-through (0x9e642262,
    xor eax,eax path) — a NULL proc has nothing to check.
    else -> replay 'cmp [rcx+0xb50], 0' + the jne.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE39  = 0x9E400C80
SITE    = 0x9E64224F
JNE_F   = 0xFFFFFFFF9E6425A5
CONT_F  = 0xFFFFFFFF9E642262

SITE_OLD = bytes.fromhex(
    "498b4c2408"              # mov rcx, [r12+8]            (5B)
    "4883b9500b000000"        # cmp qword [rcx+0xb50], 0    (8B)
    "0f8543030000"            # jne 0x9e6425a5              (6B)
)                             # 19B

CAVE39_ASM = f"""
    mov  rcx, qword ptr [r12 + 8]
    test rcx, rcx
    jnz  ok
    jmp  {CONT_F:#x}
ok:
    cmp  qword ptr [rcx + 0xb50], 0
    jne  {JNE_F:#x}
    jmp  {CONT_F:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE39_ASM, CAVE39)
if not enc:
    print("ASM FAILED"); sys.exit(1)
cave39 = bytes(enc)
print(f"cave39: {len(cave39):#x}B @ {CAVE39:#x}")
assert len(cave39) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = SITE - KTEXT
if bytes(img[off:off+len(SITE_OLD)]) != SITE_OLD:
    print(f"FAIL site {SITE:#x}: {bytes(img[off:off+len(SITE_OLD)]).hex()}")
    print(f"  expected: {SITE_OLD.hex()}")
    sys.exit(1)
off = CAVE39 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave39 {CAVE39:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

rel = CAVE39 - (SITE + 5)
off = SITE - KTEXT
img[off:off+len(SITE_OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(SITE_OLD) - 5)

off = CAVE39 - KTEXT
img[off:off+len(cave39)] = cave39

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave39 ---")
for i in md.disasm(cave39, CAVE39):
    print(f"  {i.address:#x}  {i.bytes.hex():<18} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP15#18: idle-loop NULL-proc guard (cave39 @0x9E400C80)")
