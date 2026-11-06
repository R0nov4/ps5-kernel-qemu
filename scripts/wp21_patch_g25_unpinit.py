#!/usr/bin/env python3
"""WP21 G25 — 'panic: unp_init' -> THE FN'S OWN CLEAN EXIT  [done=1158]
          (the first documented blocker AFTER 'Device configuration
           finished.' — kept as insurance for the WP22 march)

ROOT CAUSE: unp_init (0x9ed7ba40) creates the unp zone and panics when
the create answers NULL (our designed zonecreate semantics):

      0x9ed7ba5e  call 0x9e82b0e0("unp", 0xf0, ...)      ; uma_zcreate
      0x9ed7ba6e  test rax, rax
      0x9ed7bb71  je   0x9ed7bb6f                          ; <<< NULL -> panic ('unp_init')
      ...the zone setup, hash init, mtx init...
      0x9ed7bb69  pop rbp; jmp 0x9e8b7dd0                  ; the fn's own clean exit

FIX — THE LOCAL GUARD (the designed skip): retarget the je to the fn's
own clean exit at 0x9ed7bb69 — the zone-global keeps the designed NULL
and the remaining unp setup is skipped, exactly the semantics every
other zonecreate family member got in WP18. 6-byte disp32 retarget.
"""
import sys

KTEXT = 0x9E3F0000
IMG = "./wp21_kit/wp3_boot/kernel_raw.bin"

S = 0x9ED7BA71
OLD = bytes.fromhex("0f84f8000000")            # je 0x9ed7bb6f (panic block)
NEW = bytes.fromhex("0f84f2000000")            # je 0x9ed7bb69 (pop rbp; tail-jmp clean exit)

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

off = S - KTEXT
site = bytes(img[off:off+len(OLD)])
if site == NEW:
    print(f"site {S:#x} already patched (idempotent) — OK"); sys.exit(0)
if site != OLD:
    print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)

assert S + 6 + int.from_bytes(NEW[2:6], "little", signed=True) == 0x9ED7BB69

img[off:off+len(NEW)] = NEW
open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP21-G25: unp_init panic -> the fn's own clean exit @0x{S:X} — "
      f"the designed zone-unavailable skip (insurance for the WP22 march)")
