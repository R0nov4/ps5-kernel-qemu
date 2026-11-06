#!/usr/bin/env python3
"""WP29 — G51: kill the runtime domains-list 4-CYCLE (THE #1266 livelock).

USER GDB (boot7, WP28 image, @12s + 45s silence):
  rip=0x9ee30b80 (malloc small path), r12=0x102 (M_WAITOK|M_ZERO),
  rbp chain: malloc(rbp ..8970, ret 0x9e7e0670 = the G47-site call)
   <- 0x9e7e0650 rib_head_create (rbp ..8990, ret 0x9e8232a3)
   <- 0x9e823290 in_inithead (rbp ..89b0, saved r14 = 0x9e658db8 = the
      'internet' dom_rtattach THUNK, saved rbx = &rt_tables[2] = an
      ARENA pointer 0xffff8e773f71eda0)
   <- rt_tables_init 0x9e7e37c0 (stage #1266, sub 0x1d order 3) <- walk.

ROOT CAUSE (fully static-proven):
  The image's domains-list head [0xa1f0eea0] is PRE-SET (static) to
  'local' (0xa094b410) and the four domain structs are statically
  pre-linked: local -> internet6 -> internet -> route -> NULL.
  SYSINIT stages #1255..#1258 (sub 0x1d order 0) call domain_add
  (0x9ec6b0d0) for route, internet, internet6, local — each doing
  dom->next = head; head = dom.  With head NON-NULL at the first add,
  the chain closes into a 4-CYCLE:
      local -> internet6 -> internet -> route -> local -> ...
  Stage #1266 rt_tables_init then iterates the list FOREVER, calling
  dom_rtattach for internet6/internet each lap -> rib_head_create ->
  malloc(0x1a0, type 0xa0cbdaf0, 0x102) -> the arena bump (~250 laps)
  then fast-NULL forever = the 45s silence with zero crashes.
  (Proven NOT the malloc tail: cave50 0x9e401200 is a plain bump arena
  with an exhaustion check; both branches jmp 0x9eff8d39 -> clean exit
  via 0x9eff8d92; the je 0x9eff8d21 only routes NOWAIT-NULL through a
  stats counter. No loop exists inside malloc.)

G51: zero the qword at 0xa1f0eea0 (static domains head). The four
domain_adds then build the canonical FreeBSD list
local -> internet6 -> internet -> route -> NULL; #1266 finishes in
4 domain steps (2 rib_head allocations — arena has ~135KB); the walk
proceeds to the tail stages (G49 guards active) and parks (G50 emits
'WP23: sysinit walk complete; parking.' to port 0x402).

GATE: base md5 must be a7f800301bb9571039aff7ab61ce23b8 (WP28).
Idempotent. ZERO QEMU / ZERO GDB.
"""
import hashlib, struct, sys

SCRIPT_NAME = "wp29_patch_g51.py"
KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"
HEAD = 0xA1F0EEA0                    # struct domain *domains (static head)
EXPECT_BASE = "a7f800301bb9571039aff7ab61ce23b8"   # WP28 image

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704
h0 = hashlib.md5(bytes(img)).hexdigest()

cur = struct.unpack("<Q", bytes(img[HEAD - KTEXT: HEAD - KTEXT + 8]))[0]
masked = cur & 0xFFFFFFFF
if masked == 0:
    print(f"OK {SCRIPT_NAME}: already applied (head is NULL) — idempotent exit")
    sys.exit(0)
if h0 != EXPECT_BASE:
    sys.exit(f"FAIL base md5 {h0} (expected {EXPECT_BASE}) with head={masked:#x}")
if masked != 0xA094B410:
    sys.exit(f"FAIL head {HEAD:#x} unexpected value {cur:#x} (expected 0xffffffffa094b410 'local')")

img[HEAD - KTEXT: HEAD - KTEXT + 8] = b"\x00" * 8
open(IMG, "wb").write(img)
h = hashlib.md5(bytes(img)).hexdigest()
assert len(img) == 65224704
print(f"OK {SCRIPT_NAME}: domains head 0x{HEAD:X} 0xffffffffa094b410 -> 0")
print(f"OK {SCRIPT_NAME}: new md5 {h}")
