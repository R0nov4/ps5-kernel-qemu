#!/usr/bin/env python3
"""WP17 #5 — cave57 exit retarget (the double-unlock behind
         'panic: __mtx_unlock_flags: td_locks -1').

ROOT CAUSE (GDB wp17_gdb_c4 — the full arena-lock choreography):
  WP16#15's cave57 hooks the wait-fail panic-printer call @0x9e9d7040 and
  jumps to 'the designed NOWAIT-fail return' 0x9e9d7066 -> 0x9e9d6ff6
  (the TAIL unlock). But the lock state at 0x9e9d7040 is ALREADY RELEASED:
  the wait-fail path unlocks at 0x9e9d7028 BEFORE the 'test al,1' branch,
  and the designed NOWAIT exit at 0x9e9d703e jumps to 0x9e9d7001 (the
  counter-check + epilogue — NO further unlock). 0x9e9d7066's tail unlock
  is correct ONLY for the FLIP path (WP14-C: the sleep block, where the
  post-extend re-lock @0x9e9d6b19 still holds the lock).
  => every wait-fail-with-WAITOK flow through cave57 = unlock TWICE:
     per-iteration td_locks -= 1 -> after the retry: 0 -> -1 -> PANIC.

FIX — retarget cave57's final jump: 0x9e9d7066 -> 0x9e9d7001 (the exit
  that matches the lock state at the hook point: the lock released at
  0x9e9d7028, ebx=0xc already set by the wait-fail flow).
  The FLIP (WP14-C) is untouched: its 0x9e9d7066 target keeps the correct
  held-lock tail unlock.
"""
import sys
import struct

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE57 = 0x9E401580
JMP_VA = 0x9E401591                      # cave57's final 'jmp 0x9e9d7066'
OLD_TGT = 0x9E9D7066                     # the WRONG exit (the tail unlock) — short va
NEW_TGT = 0x9E9D7001                     # the CORRECT exit (no unlock) — short va

img = bytearray(open(IMG, "rb").read())

off = JMP_VA - KTEXT
cur = bytes(img[off:off+5])
if cur[0] != 0xE9:
    print(f"FAIL cave57 jump site {JMP_VA:#x}: {cur.hex()} (not a jmp)"); sys.exit(1)
cur_tgt = (JMP_VA + 5 + struct.unpack("<i", cur[1:5])[0]) & 0xFFFFFFFF
if cur_tgt == NEW_TGT:
    print(f"cave57 jump already retargeted -> {NEW_TGT:#x} (idempotent)")
    sys.exit(0)
if cur_tgt != OLD_TGT:
    print(f"FAIL cave57 jump target {cur_tgt:#x} (expected {OLD_TGT:#x})"); sys.exit(1)

rel = NEW_TGT - (JMP_VA + 5)
img[off:off+5] = b"\xe9" + struct.pack("<i", rel)
print(f"cave57 @ {JMP_VA:#x}: jmp {OLD_TGT:#x} -> jmp {NEW_TGT:#x} (the lock-released exit)")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP17#5: cave57 exit retarget (kills the double-unlock td_locks panic)")
