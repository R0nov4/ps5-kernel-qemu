#!/usr/bin/env python3
"""WP16 #2 — gs:[8] (pc_idlethread) reseed: the fake zero object -> thread0.

ROOT CAUSE (GDB, boot test #1 with cave43):
  choosethread (0x9ea925e0) with an EMPTY run queue falls back to
  PCPU(idlethread) = gs:[8] = the WP15#11/#14/#15-seeded fake zero object
  @DMAP(0x3F190000) — td_pcb NULL, td_proc NULL. mi_switch then runs the
  newtd != oldtd path: the lock hand-off 0x9e8b7c90(rdi=newtd, rsi=sched)
  sets fake->td_lock = sched lock (0xa1d04bf8), and 0x9eaa5d67
  'mov [sched+0x18], r13' TRANSFERS the sched-lock OWNERSHIP to the fake
  object right before cpu_switch. cave43's no-op return then leaves the
  sched lock owned by a zombie -> the vmwait retry spins 183x on it ->
  'panic: spin lock held too long (held by 0xffff8e773f190000 tid 0)'.

FIX (the designed FreeBSD early-boot semantics — thread0 IS the idle
  thread until the real idle kthreads are created):
  point gs:[8] at thread0 (0xffffffffa1978860, the static boot thread):
    - image seed  [0xa1fb8f08] : DMAP(0x3F190000) -> thread0
    - cave33 (@0x9E400980) movabs rax fallback imm -> thread0
    - cave36 (@0x9E400B00) movabs rbx fallback imm -> thread0
  Then choosethread's empty-runq answer == curthread == oldtd and
  mi_switch takes its DESIGNED same-thread path (r15b=1: 0x9eaa5d33 sets
  td_lock = sched lock, jumps straight to the 0x9eaa5ea2 epilogue — no
  cpu_switch call at all, no ownership transfer, clean return to the
  sleep path so thread0 keeps executing SYSINIT).
  Field readers of gs:[8] now see a REAL thread (live-residue priority
  +0x3c4, TDP flags +0xed) instead of zeros — the designed answers.
"""
import struct

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

THREAD0 = 0xFFFFFFFFA1978860          # proc0/thread0 (SceSwapper) static obj
OLD_SEED = 0xFFFF8E773F190000         # DMAP(0x3F190000) fake zero object

CAVE33 = 0x9E400980
CAVE36 = 0x9E400B00

img = bytearray(open(IMG, "rb").read())

# --- [1] image seed: [0xa1fb8f08] ---
off = 0xA1FB8F08 - KTEXT
old = struct.unpack_from("<Q", img, off)[0]
if old != OLD_SEED and old != THREAD0:
    print(f"FAIL pcpu+8 seed @{0xA1FB8F08:#x} = {old:#018x}")
    raise SystemExit(1)
struct.pack_into("<Q", img, off, THREAD0)
print(f"[0xa1fb8f08] (pcpu gs:[8] image seed): {old:#x} -> {THREAD0:#x}")

# --- [2] cave33 movabs rax imm (the NULL fallback value) ---
OLD33 = bytes.fromhex("48b80000193f778effff")          # movabs rax, OLD_SEED
NEW33 = b"\x48\xb8" + struct.pack("<Q", THREAD0)
off = CAVE33 - KTEXT
win = bytes(img[off:off+0x50])
if OLD33 in win:
    img[off:off+0x50] = win.replace(OLD33, NEW33, 1)
    print(f"cave33 @{CAVE33:#x}: movabs rax {OLD_SEED:#x} -> {THREAD0:#x}")
elif NEW33 in bytes(img[off:off+0x50]):
    print(f"cave33 @{CAVE33:#x}: already {THREAD0:#x}")
else:
    print("FAIL cave33 movabs not found"); raise SystemExit(1)

# --- [3] cave36 movabs rbx imm ---
OLD36 = bytes.fromhex("48bb0000193f778effff")          # movabs rbx, OLD_SEED
NEW36 = b"\x48\xbb" + struct.pack("<Q", THREAD0)
off = CAVE36 - KTEXT
win = bytes(img[off:off+0x50])
if OLD36 in win:
    img[off:off+0x50] = win.replace(OLD36, NEW36, 1)
    print(f"cave36 @{CAVE36:#x}: movabs rbx {OLD_SEED:#x} -> {THREAD0:#x}")
elif NEW36 in bytes(img[off:off+0x50]):
    print(f"cave36 @{CAVE36:#x}: already {THREAD0:#x}")
else:
    print("FAIL cave36 movabs not found"); raise SystemExit(1)

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP16#2: gs:[8] idlethread -> thread0 (image + cave33 + cave36)")
