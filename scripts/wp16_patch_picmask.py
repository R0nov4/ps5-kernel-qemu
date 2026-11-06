#!/usr/bin/env python3
"""WP16 #3 — one-shot 8259 PIC mask at critical_exit (false 'double fault').

ROOT CAUSE (QEMU -d int, event 0 — 'Servicing hardware INT=0x08'):
  The kernel boots with IF=0 all the way through the SYSINIT stages (no
  interrupt was ever delivered — the -d int log's first event is this
  one). The FIRST interrupt-enable is the sleep path's critical_exit
  (0x9edfa1b0): td->td_critnest-- reaches 0 -> 'push rax; popfq' restores
  the saved rflags with IF (0x9edfa1d3/d4) -> the PENDING PIC interrupt
  line (PIT/RTC — the 8259s were never remapped by this boot: vector 8!)
  is delivered IMMEDIATELY at 0x9edfa1d5 ('add rsp,8' — QEMU event 0,
  SP=0xa22287e0, RDI=sched-lock-word, RSI=sched-lock-obj).
  INT 8 through IDT[8] = the #DF handler (IST gate): an IRQ delivery
  pushes NO error code, so the handler's frame math is shifted 8 bytes —
  it prints tf_cs (0x20) as 'rip' and tf_ss (0x28) as 'rsp', then
  'panic: double fault', then its own misaligned swapgs/frame reads fault
  (event 1+: #PF CR2=0x34 at 0x9e7df317, recursive IST #PFs) -> death.

FIX (the designed early-boot behavior — mask everything until the ICU
  SYSINIT remaps the PICs to vectors 0x28+):
  cave44 @0x9E400F00 replacing critical_exit's entry
  [0x9edfa1b0, 0x9edfa1bb) ('push rbp; mov rbp,rsp; push rbx; push rax',
  6B):
    ONE-SHOT (flag byte @DMAP 0x3F1A0800 — free space in the pcb seed
    page, only [+0,+0x120) is ever read):
        out 0x21, 0xFF   ; mask ALL master IRQs (incl. IRQ0 PIT + cascade)
        out 0xA1, 0xFF   ; mask ALL slave IRQs (incl. IRQ8 RTC)
    then replay the prologue and continue at 0x9edfa1bb.
  The mask lands BEFORE the popfq that enables IF, so the pending PIC
  line is masked at the exact first-delivery moment. When the ICU setup
  SYSINIT eventually runs it takes the PICs over with its own
  ICW/remap/unmask — the designed behavior from then on.
  The one-shot flag keeps the overhead to a single byte-read on every
  later critical_exit (no interference with the late ICU state).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE44 = 0x9E400F00
S44, S44E = 0x9EDFA1B0, 0x9EDFA1B6          # push rbp; mov rbp,rsp; push rbx; push rax (6B)
                                            # (return target 0x9EDFA1B6 = 'mov rbx,gs:[0]'
                                            # — v1 jumped to 0x9EDFA1BB = mid-instruction:
                                            # the gs:[0] load was skipped, rbx kept the
                                            # caller's value (0x101) -> CR2 0x589 crash!)
FLAG  = 0xFFFF8E773F1A0800                   # one-shot flag (pcb seed page +0x800)

OLD44 = bytes.fromhex(
    "55"              # push rbp
    "4889e5"          # mov rbp, rsp
    "53"              # push rbx
    "50"              # push rax
)

C44 = f"""
    movabs rax, {FLAG:#x}
    cmp  byte ptr [rax], 0
    jne  done
    mov  byte ptr [rax], 1
    mov  dx, 0x21
    mov  al, 0xff
    out  dx, al
    mov  dx, 0xa1
    out  dx, al
done:
    push rbp
    mov  rbp, rsp
    push rbx
    push rax
    jmp  {0xFFFFFFFF9EDFA1B6:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C44, CAVE44)
print(f"cave44: {len(code):#x}B @ {CAVE44:#x}  hook {S44:#x} ({len(OLD44)}B)")
assert len(code) <= 0x80, "cave44 too big"

img = bytearray(open(IMG, "rb").read())

off = S44 - KTEXT
site = bytes(img[off:off+len(OLD44)])
if site[:1] == b"\xe9":
    rel_expect = CAVE44 - (S44 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S44:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S44:#x}: already hooked to cave44 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD44:
        print(f"FAIL site {S44:#x}: {site.hex()} (expected {OLD44.hex()})"); sys.exit(1)
    hooked = False

off = CAVE44 - KTEXT
cur = bytes(img[off:off+0x80])
if not all(b == 0xCC for b in cur):
    # v1 body present (idempotent rerun) — blank the window and rewrite
    if cur[:8] == bytes.fromhex("48b800081a3f778e"):   # v1 head: movabs rax, FLAG
        img[off:off+0x80] = b"\xcc" * 0x80
        print(f"cave {CAVE44:#x}: v1 body found — blanking for rewrite")
    else:
        print(f"FAIL cave {CAVE44:#x} not pristine CC and not v1"); sys.exit(1)
print("site + cave assertions OK")

md = Cs(CS_ARCH_X86, CS_MODE_64)
insns = list(md.disasm(code, CAVE44))
# encoding sanity: the two 'out dx, al' (ee) and the movabs flag load
n_out = sum(1 for i in insns if i.mnemonic == "out")
if n_out != 2:
    for i in insns:
        print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
    print("FAIL: expected exactly 2 out instructions"); sys.exit(1)

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE44 - (S44 + 5)
    off = S44 - KTEXT
    img[off:off+len(OLD44)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD44) - 5)

print("--- cave44 ---")
for i in insns:
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP16#3: one-shot PIC mask at critical_exit (cave44)")
