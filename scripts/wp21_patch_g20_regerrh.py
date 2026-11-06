#!/usr/bin/env python3
"""WP21 G20 — 'Failed register error handler. ret=16' PANIC -> TOLERATED
          (a known blocker between done=1006 and 'Device configuration
           finished.' — the user's WP21 cheat-sheet family)

ROOT CAUSE: the error-handler registration fn 0x9ecafed0 (the deep-boot
dce/registry stage) registers its handler and treats ANY non-zero
return as fatal:

      0x9ecb0062  lea  rdi, [rip - 0x653b81]       ; the handler fn
      0x9ecb006b  call 0x9ecb12f0                  ; register_error_handler(fn, 0)
      0x9ecb0070  test eax, eax
      0x9ecb0072  jne  0x9ecb026e                   ; <<< ret != 0 -> panic
                                                    ('Failed register error handler. ret=%d')
The registration answers ret=16 (EBUSY-class) on our boot because the
registry state comes from the cold-boot path, not a real console cycle.

FIX — THE LOCAL GUARD (the designed tolerance): NOP the 6-byte jne —
a failed registration then simply flows into the fn's normal continue
path (locks, prints, remaining registrations, its own epilogue). The
handler is merely not registered; nothing else in the fn depends on it.
"""
import sys

KTEXT = 0x9E3F0000
IMG = "./wp21_kit/wp3_boot/kernel_raw.bin"

S = 0x9ECB0072
OLD = bytes.fromhex("0f85f6010000")            # jne 0x9ecb026e (panic block)
NEW = bytes.fromhex("909090909090")            # nop x6 — tolerate the ret

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
print(f"OK WP21-G20: 'Failed register error handler' panic NOPed @0x{S:X} — "
      f"the designed tolerance for ret=16")
