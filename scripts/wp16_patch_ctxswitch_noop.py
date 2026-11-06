#!/usr/bin/env python3
"""WP16 #1 — cpu_switch no-op guard (crash: double fault @0x9e642348, rsp=0x0).

ROOT CAUSE (GDB-confirmed, wmesg='vmwait'):
  thread0 (SceSwapper, mid-SYSINIT) fails a VM allocation -> vmwait() ->
  sleepq chain (subr_sleepqueue.c) -> mi_switch(0x9eaa5a60) -> choosethread
  (0x9ea925e0) finds an EMPTY run queue -> returns PCPU(idlethread) =
  gs:[8] = the WP15-seeded fake zero object @DMAP(0x3F190000) -> cpu_switch
  (oldtd=rdi=thread0 [td_pcb=0xa2228a40 VALID], newtd=rsi=fake idle
  [td_pcb=NULL, td_proc=NULL], mtx=rdx).
  WP15 #19 cave40 redirected the NULL pcb to the zero seed page; the
  register-restore block (0x9e642329..0x9e642344) then loads rsp/rbp/rip
  from the ZERO page -> rsp=0x0 -> 'mov [rsp],rax' @0x9e642348 faults on
  the NULL stack -> Fatal double fault.

FIX (user-specified semantics — "keep thread0 in place, return cleanly"):
  cave43 @0x9E400E80 replacing cpu_switch's entry [0x9e642160, 0x9e642167)
  ('mov r8,[rdi+0x3f8]', 7B):
    - newtd->td_pcb ([rsi+0x3f8]) == NULL            -> no-op switch
    - pcb->pcb_rsp ([pcb+0x28]) == 0 (zero pcb page) -> no-op switch
    - pcb->pcb_rip ([pcb+0x38]) == 0                 -> no-op switch
  A bare 'ret' at the very entry touches no context/td_lock/pmap state —
  cpu_switch has modified nothing yet at that point. mi_switch's
  post-call code (0x9eaa5e5e: gs:[0x34], [rbx+8]->proc AST check,
  [rbx+0x524/0x602]) runs with rbx still = oldtd = thread0 — consistent —
  and returns up through the sleep path so thread0 retries the VM
  allocation and the SYSINIT loop continues.

  v2 (boot test #1 lesson — 'panic: spin lock held too long', waiter 183,
  held by the fake idle): mi_switch 0x9eaa5d67 transfers the per-CPU
  sched-lock OWNERSHIP ('mov [sched+0x18], r13') to the pcb-less newtd
  right BEFORE calling cpu_switch. The no-op return must UNDO it: in the
  no_switch path, read the per-cpu sched lock object
  ([gs:[0x34]*64 + 0xa1d04c18]), and if its word ([obj+0x18]) still
  contains newtd (rsi), release it (word := 4, the designed free state —
  same store the unlock helper 0x9e8b7cda performs). Guarded: only when
  the word == the transferred newtd, so a legitimately-held lock is never
  clobbered.

  Valid newtd (real pcb with non-zero rsp/rip) -> replay the replaced
  instruction and jump back to 0x9e642167: the designed switch path runs
  untouched (caves 40/41/42 stay as defense-in-depth for late paths).
  NOTE: with WP16#2 (gs:[8] -> thread0) the pcb-less switch never comes
  from mi_switch anymore; cave43 remains the safety net for any later
  SYSINIT-created thread with a missing pcb.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE43 = 0x9E400E80
S43, S43E = 0x9E642160, 0x9E642167          # 'mov r8,[rdi+0x3f8]' (7B)

OLD43 = bytes.fromhex("4c8b87f8030000")     # mov r8, qword ptr [rdi+0x3f8]

C43 = f"""
    mov  rax, qword ptr [rsi + 0x3f8]
    test rax, rax
    jz   no_switch
    cmp  qword ptr [rax + 0x28], 0
    je   no_switch
    cmp  qword ptr [rax + 0x38], 0
    je   no_switch
    mov  r8, qword ptr [rdi + 0x3f8]
    jmp  {0xFFFFFFFF9E642167:#x}
no_switch:
    mov  ecx, dword ptr gs:[0x34]
    shl  rcx, 6
    mov  rcx, qword ptr [rcx + 0xa1d04c18]
    test rcx, rcx
    jz   just_ret
    cmp  qword ptr [rcx + 0x18], rsi
    jne  just_ret
    mov  qword ptr [rcx + 0x18], 4
just_ret:
    ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C43, CAVE43)
print(f"cave43: {len(code):#x}B @ {CAVE43:#x}  hook {S43:#x} ({len(OLD43)}B)")
assert len(code) <= 0x80, "cave43 too big"

img = bytearray(open(IMG, "rb").read())

# verify the [rcx + 0xa1d04c18] encoding: 48 8b 89 <disp32=a1d04c18>
# (capstone renders the sign-extended disp as '- 0x5e2fb3e8'; the CPU
# computes rcx + 0xffffffffa1d04c18 which IS the kernel VA we want)
md = Cs(CS_ARCH_X86, CS_MODE_64)
insns = list(md.disasm(code, CAVE43))
ok_enc = any(i.bytes == bytes.fromhex("488b89184cd0a1") for i in insns)
if not ok_enc:
    for i in insns:
        print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
    print("FAIL: [rcx + 0xa1d04c18] not encoded as expected disp32")
    sys.exit(1)

off = S43 - KTEXT
site = bytes(img[off:off+len(OLD43)])
hooked = site[:1] == b"\xe9"
if not hooked:
    if site != OLD43:
        print(f"FAIL site {S43:#x}: {site.hex()} (expected {OLD43.hex()})")
        sys.exit(1)
elif hooked:
    rel_expect = CAVE43 - (S43 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S43:#x} hooked elsewhere: {site[:5].hex()}")
        sys.exit(1)
    print(f"site {S43:#x}: already hooked to cave43 (idempotent rewrite)")

off = CAVE43 - KTEXT
# blank the old cave body window back to CC (idempotent rerun)
img[off:off+0x80] = b"\xcc" * 0x80
img[off:off+len(code)] = code

if not hooked:
    rel = CAVE43 - (S43 + 5)
    off = S43 - KTEXT
    img[off:off+len(OLD43)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD43) - 5)

print("--- cave43 (v2) ---")
for i in insns:
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP16#1: cpu_switch no-op guard + sched-lock undo (cave43 v2)")
