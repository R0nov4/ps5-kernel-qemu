#!/usr/bin/env python3
"""WP21 G17 — THE STATS-POLL FAMILY GUARD  [the user's hypothesis (a)]
          (the 'caller that loops on the stats-lookup 0 answer')

ROOT CAUSE: the counter-lookup fn 0x9edd41d0 (G11: NULL table -> ebx=0)
is polled by the wait family, e.g. 0x9e78b3c0:

      fn(counter_id, mask, shift, expected, poll_ms, retries):
        do { eax = lookup(counter_id);          <<< G11 answers 0 (no table)
             eax = (eax & mask) >> shift
             if (eax == expected) return matched
             pause-spin(poll_ms*100)
        } while (++tries < retries)

With the table never allocated the condition can never be observed, so
every poll burns its full retry budget (callers pass up to 0x2710 tries,
and the >999-try warning path re-prints); under TCG several such polls
stack into the appearance of a hang.

FIX — THE LOCAL GUARD (the designed not-matched answer): hook the entry
of the generic poll-wait 0x9e78b3c0 — if the stats table [0xa1f9a538]
is NULL, answer 0 (not matched) immediately, exactly what the fn itself
returns when its retry budget is exhausted (r12b=0 -> eax=0). With a
live table the original poll runs unchanged. Slot 0x9E403C80.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./wp21_kit/wp3_boot/kernel_raw.bin"

SLOT = 0x9E403C80                     # first free WP21 slot (G14 ended at 0x9E403C00)
S = 0x9E78B3C0                        # the generic stats poll-wait fn
OLD = bytes.fromhex("554889e54157")   # push rbp; mov rbp,rsp; push r15 (6B)
CONT = 0xFFFFFFFF9E78B3C6             # push r14 (the next original insn)
TBL = 0xFFFFFFFFA1F9A538              # the stats table global (G11's)

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

C = f"""
    movabs r10, {TBL:#x}
    mov    r10, qword ptr [r10]
    test   r10, r10
    jnz    real
    xor    eax, eax
    ret
real:
    push   rbp
    mov    rbp, rsp
    push   r15
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
    img[off:off+len(OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90"

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP21-G17: stats-poll NULL-table guard @0x{S:X} (slot 0x{SLOT:X}) — "
      f"the designed not-matched answer for the never-allocated table")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
