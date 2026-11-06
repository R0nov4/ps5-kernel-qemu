#!/usr/bin/env python3
"""WP21 G24 — 'procdesc_init: procdesc_zone not initialized' PANIC -> SKIP
          (a known blocker between done=1006 and 'Device configuration
           finished.' — the user's WP21 cheat-sheet family)

ROOT CAUSE: procdesc_init (0x9f024ba0) creates its zone and panics when
the create answers NULL (our designed zonecreate semantics):

      0x9f024bbe  call 0x9e82b0e0("procdesc", 0x88, ...)   ; uma_zcreate
      0x9f024bce  test rax, rax
      0x9f024bd1  je   0x9f024bd5                            ; <<< NULL -> panic
                                                               ('procdesc_init: procdesc_zone not initialized')
      0x9f024bd3  pop rbp; ret                               ; the clean exit, 2 bytes later

FIX — THE LOCAL GUARD (the designed skip): NOP the 2-byte je — the NULL
zone then falls straight into the fn's own 'pop rbp; ret'. The zone
pointer global keeps the designed NULL; the procdesc stage is skipped
exactly like every other zonecreate family member since WP18.
"""
import sys

KTEXT = 0x9E3F0000
IMG = "./wp21_kit/wp3_boot/kernel_raw.bin"

S = 0x9F024BD1
OLD = bytes.fromhex("7402")                  # je 0x9f024bd5 (panic block)
NEW = bytes.fromhex("9090")                  # nop x2 -> fall into pop rbp; ret

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

off = S - KTEXT
site = bytes(img[off:off+len(OLD)])
if site == NEW:
    print(f"site {S:#x} already patched (idempotent) — OK"); sys.exit(0)
if site != OLD:
    print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)

img[off:off+len(NEW)] = NEW
open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP21-G24: procdesc_init panic NOPed @0x{S:X} — the designed "
      f"zone-unavailable skip")
