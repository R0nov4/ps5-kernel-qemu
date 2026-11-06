#!/usr/bin/env python3
"""WP21 G27 — THE CPUSTATE SLOT-TABLE BOUND GUARD  [NEW FRONTIER #1]
          (Fatal trap 12 @ 0xffffffff9e968a55, CR2=0x34fa199e6e0 READ —
           right after the '[MP1ERROR] : init_cpupstate: N unexpected
           did: 0' prints, ~20 entries past the hdcp frontier)

ROOT CAUSE: the slot-allocator fn 0x9e968a00 (reached via the indirect
thunk 0x9e65e9f8 from the MP1 cpupstate stage) scans a fixed record
table for a free slot:

      0x9e968a24  mov  eax, r14d                       ; eax = edi (record idx)
      0x9e968a27  lea  rcx, [rip + 0x3035fb2]          ; the table @ 0xa199e9e0
      0x9e968a2e  imul rax, rax, 0x350                 ; stride 0x350
      0x9e968a35  lea  rdx, [rax + rcx + 0x50]
      ...r15 = 0..0x6f scan: 0x9e968a55 cmp dword [rdx + r15*4], -1

GDB-solved from the trap frame: r15=0x10, so edi = 0xffb2b78b — a wild
~4.29e9 record index (an uninitialized residual u32 consumed as an
index by the MP1 stage), and the computed record address
0x34fa199e6e0 is unmapped.

FIX — THE LOCAL GUARD (the fn's own designed exhaustion answer): hook
the table-base lea — eax >= 0x100 (any sane record bound; the table is
a small fixed array) jumps straight to the fn's OWN exhaustion exit
0x9e968a6a ('xor r14d,r14d' -> unlock the entry lock 0x9e8b7520 ->
'mov eax,r14d' -> pops -> ret = "no free slot"), which balances the
entry lock taken at 0x9e968a1f. Valid indices replay the lea (movabs
form) and continue the original scan. Slot 0x9E403F80.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./wp21_kit/wp3_boot/kernel_raw.bin"

SLOT = 0x9E403F80
S = 0x9E968A27                          # lea rcx, [rip+0x3035fb2] (7B)
OLD = bytes.fromhex("488d0db25f0303")
CONT = 0xFFFFFFFF9E968A2E               # imul rax, rax, 0x350
EXIT = 0xFFFFFFFF9E968A6A               # the designed exhaustion exit
TBL = 0xFFFFFFFFA199E9E0                # the record table base

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

C = f"""
    cmp    eax, 0x100
    jb     real
    jmp    {EXIT:#x}
real:
    movabs rcx, {TBL:#x}
    jmp    {CONT:#x}
"""
code = asm(C, SLOT)
assert len(code) <= 0x80, f"slot code too big: {len(code):#x}"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

off = S - KTEXT
site = bytes(img[off:off+len(OLD)])
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
    img[off:off+len(OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * 2

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP21-G27: cpupstate slot-table bound guard @0x{S:X} (slot 0x{SLOT:X}) — "
      f"wild indices get the fn's own 'no free slot' exhaustion answer")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
