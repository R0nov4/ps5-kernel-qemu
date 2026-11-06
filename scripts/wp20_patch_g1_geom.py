#!/usr/bin/env python3
"""WP20 G1 — THE GEOM UNLOCK (the user's plan #1): g_waitfor_event,
  the SYSINIT IDX 735 stall.  [2-byte in-place edit, no cave]

THE STALL (the user's GDB finding): sysinit IDX 735/1236 (the GEOM
  'g_blk' class registration) calls g_post_event_x, which posts an
  EV_WAIT event and then WAITS for the GEOM worker threads to mark it
  EV_DONE:

    0x9ebabaa2  mov  r14d, [rbx + 0x20]      ; ep->flag
    0x9ebabaa6  test r14d, 0x80000           ; EV_DONE?
    0x9ebabaad  jne  0x9ebabaf9              ; done -> exit   (75 4a)
    0x9ebabaaf  lea  r15, [rip + ...]        ; "g_waitfor_event"
    ...        <the msleep retry loop — forever>
    0x9ebabaf9  <exit>: shl/sar/and r14d     ; result = flag bit 17
                mtx_unlock(&g_eventlock); g_free(ep); ret

  The g_down/g_up workers were never created (kthread -> fork1 ->
  zone NULL -> error 12 — the WP18 designed semantics, KEPT), so
  EV_DONE never arrives and the whole march parks at IDX 735.

THE USER'S FIX (applied verbatim): 0x9ebabaad  '75 4a' (jne) -> 'eb 4a'
  (jmp).  The completion check becomes UNCONDITIONAL: every
  g_waitfor_event returns its DESIGNED result immediately (r14d was
  loaded before the jump; flag bit 17 is clear -> result 0 = success),
  the lock is released and the event freed through the fn's own exit.
  The GEOM class registrations complete; the march prints the
  'firmware taskq' stage and walks on.  fork1/proc_create untouched.

  (The alternative offered by the user — an EV_DONE guard at
  0x9ebabaec — is NOT needed: the unconditional exit is strictly
  simpler and reaches the same designed code.)
"""
import sys

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

S = 0x9EBABAAD                       # jne 0x9ebabaf9 (2B) — the completion check
OLD = bytes.fromhex("754a")          # jne +0x4a  -> the exit
NEW = bytes.fromhex("eb4a")          # jmp +0x4a  -> ALWAYS the exit

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

off = S - KTEXT
site = bytes(img[off:off + len(OLD)])
if site == NEW:
    print(f"site {S:#x}: already unlocked (idempotent)")
    sys.exit(0)
if site != OLD:
    print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()} (expected the jne)")
    sys.exit(1)

img[off:off + len(NEW)] = NEW
open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"

print(f"OK WP20-G1: g_waitfor_event completion check jne->jmp @ {S:#x} "
      f"({OLD.hex()} -> {NEW.hex()}) — SYSINIT IDX 735 unlocked, 'firmware taskq' next")
