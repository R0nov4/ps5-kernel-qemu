#!/usr/bin/env python3
"""WP15 #14 — pcpu gs:[8] seed (crash 0x9eaa5df3, CR2=0xed; family fix).

ROOT CAUSE: the real pcpu @0xffffffffa1fb8f00 (machine_init wrmsr
MSR_GS_BASE +0x2D7 — see the trampoline comment) has its +8 field
(gs:[8] — the curpcb-ish object, live value DMAP(0x1794690)) wiped by
WP12's below-kernel DMAP-pointer wipe, and the runtime re-allocation
never happens on our boot. The AP/per-CPU module dereferences it
repeatedly:
    0x9eaa5df3  movzx eax, byte [r13 + 0xed]     <<< CRASH (r13==NULL)
    0x9eaa5e11  movzx eax, word [r13 + 0x3c4]
    (and the AP-state loop marks [obj + 0x400] = 2/4)
  All those field reads on a zero object return the designed '0'
  answers; the +0x400 state marks land in the object harmlessly.

FIX: seed the pcpu's +8 with a fresh zero page:
    [0xa1fb8f08] := DMAP(0x3F190000)
  ([0x3F190000, 0x3F1A0000) free: above the vm_dom block seed
  [0x3F170000,0x3F190000), below the node chains 0x3F1[4-7]0000 —
  inside the SMAP-reserved window, never page-ified.)
  With the seed: cave33 (WP15#11) and cave34 (WP15#12) take their
  normal paths (rax = the seed pointer != 0) and the reads return 0.
"""
import struct

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

PCPU8 = 0xA1FB8F08
SEED  = 0xFFFF8E773F190000        # DMAP(0x3F190000)

img = bytearray(open(IMG, "rb").read())

off = PCPU8 - KTEXT
old = struct.unpack_from("<Q", img, off)[0]
if old != 0:
    print(f"FAIL pcpu+8 @{PCPU8:#x} = {old:#018x} (expected 0)")
    raise SystemExit(1)
struct.pack_into("<Q", img, off, SEED)
print(f"[{PCPU8:#x}] (pcpu gs:[8]) := {SEED:#018x}")

open(IMG, "wb").write(img)
print("OK WP15#14: pcpu gs:[8] seed -> DMAP(0x3F190000)")
