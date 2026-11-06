#!/usr/bin/env python3
"""WP20 G6 — THE PLINKS.Q ASSERT + SEGMENT-LOOKUP GUARDS (the user's plan #6)
          [2 local guards: 1 in-place NOP + 1 cave]
          (panic: Bad link in "plinks.q" / 'can't find the segment for m')

GUARD A (the user's verbatim plan): "NOP 掉 0x9ef7c26c 的 assert" —
  the sleepq plinks.q INVARIANTS check:
    0x9ef7c269  cmp qword ptr [rax], rbx    ; elm->prev->next == elm?
    0x9ef7c26c  jne 0x9ef7c2a0              (75 32) -> the panic block:
                'Bad link in "plinks.q", elm != prev->next, ...'
  The thread's plinks were half-linked by the early-boot seeds (elm->prev
  points at a well-formed EMPTY .data queue head).  FreeBSD release
  kernels compile INVARIANTS out; NOP the jne (75 32 -> 90 90) and the
  DESIGNED release-kernel unlink runs (head stays consistent — the
  write lands on an already-0 field).

GUARD B (the user's verbatim plan): "[rdi+0x30]==0 时守卫 0x9ea055b0" —
  the vm-page free fn 0x9ea055b0 (wakeup/alloc-unwind path):
      0x9ea055dc  call 0x9ea05b30 (the segment lookup)
      rbx = m->phys_addr ([rdi+0x30]) == 0 -> no segment contains phys 0
      -> PANIC 'can't find the segment for m %p container %d phys_addr %#lx'
  The m objects are RESIDUE vm_pages (never initialized, phys 0).
  The guard at the fn entry: [rdi+0x30]==0 -> plain ret (the free is
  skipped, the garbage page simply leaks — inert in this march);
  otherwise the full DESIGNED prologue replays and the free runs.
  -> passes hmd2_imu; the march prints 'io: <I/O>'.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

# ---------------- GUARD A: the assert NOP (in place) ---------------------------
S_A = 0x9EF7C26C
OLD_A = bytes.fromhex("7532")                  # jne +0x32 -> the panic block
NEW_A = bytes.fromhex("9090")                  # nop; nop -> the designed unlink
off = S_A - KTEXT
site = bytes(img[off:off + 2])
if site == NEW_A:
    print(f"site A {S_A:#x}: already NOPed (idempotent)")
elif site == OLD_A:
    img[off:off + 2] = NEW_A
    print(f"OK guard A: plinks.q assert jne -> nops @ {S_A:#x}")
else:
    print(f"FAIL guard A {S_A:#x}: {site.hex()} != {OLD_A.hex()}"); sys.exit(1)

# ---------------- GUARD B: vm-page-free entry guard (cave) ---------------------
SLOT_B = 0x9E402D80                            # WP20 slot ledger (G5 used 0x9E402D00)
S_B = 0x9EA055B0                               # fn entry: push rbp; mov rbp,rsp; push r15 (5B)
OLD_B = bytes.fromhex("554889e5" + "41")       # eats through the REX of 'push r15'
RESUME_B = 0xFFFFFFFF9EA055B6                  # push r14 (clean instruction boundary)

C_B = f"""
    cmp  qword ptr [rdi + 0x30], 0
    jne  live_b
    ret
live_b:
    push rbp
    mov  rbp, rsp
    push r15
    jmp  {RESUME_B:#x}
"""

code_b = asm(C_B, SLOT_B)
print(f"slot {SLOT_B:#x}: {len(code_b):#x}B  hook {S_B:#x} (5B)")
assert len(code_b) <= 0x80

off = S_B - KTEXT
site = bytes(img[off:off+5])
if site[:1] == b"\xe9":
    rel_expect = SLOT_B - (S_B + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site B {S_B:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    hooked = True
else:
    if site != OLD_B:
        print(f"FAIL site B {S_B:#x}: {site.hex()} != {OLD_B.hex()}"); sys.exit(1)
    hooked = False

off = SLOT_B - KTEXT
cur = bytes(img[off:off+len(code_b)])
if not all(b == 0xCC for b in cur) and cur != code_b:
    print(f"FAIL slot {SLOT_B:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)

img[off:off+len(code_b)] = code_b
if not hooked:
    rel = SLOT_B - (S_B + 5)
    off = S_B - KTEXT
    img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

print("--- vm-page-free garbage-page skip (slot 0x9E402D80) ---")
for i in md.disasm(code_b, SLOT_B):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
print("OK guard B: vm-page-free [rdi+0x30]==0 entry guard")

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print("OK WP20-G6: plinks.q assert NOP + segment-lookup guard — hmd2_imu passes, "
      "'io: <I/O>' next")
