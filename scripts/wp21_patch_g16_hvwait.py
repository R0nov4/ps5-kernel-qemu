#!/usr/bin/env python3
"""WP21 G16 — THE done=1006 UNSTUCK  [THE FRONTIER FIX]
          (the stall the WP20 kit ended on: serial goes silent right after
           'hdcp packet is set to 1' — the kernel is ALIVE but parked forever)

ROOT CAUSE (static forensics, no GDB spent): the sysinit thunk that prints
the hdcp landmark is the av/system-init body 0x9e8692d0 (reached via the
modevent stub 0x9e8692c0). Its flow:

      ... counter RMW (G11-guarded, safe) ...
      0x9e86938b  call 0x9eaf0bb0            ; av_init — PRINTS 'hdcp packet is set to 1'
      0x9e869395  call 0x9ea52730(0xea60)    ; <<< THE STALL: a 60s hypervisor settle-wait
      ... counter RMW + two bounded retry loops (ebx=0x3e8 x delay(100)) ...
      0x9e86958a  tail-jmp 0x9edd5030        ; last counter write, then ret

0x9ea52730 builds the notification packet {magic 0x80100000000, timeout
0xea60} and hands it to the 0x2e gateway (0x9e78b3b0 -> 0x9effeaa0 ->
0x9e8e7c50) — on real hardware the hypervisor completes the wait; on our
QEMU boot the completion never arrives, so the thunk never returns, the
walker never stamps it, and done freezes at 1006 with the kernel alive
but silent (the WP20 patient-boot's 3-minute-silence stop matches an
unbounded wait, not the 60s sleep).

FIX — THE LOCAL GUARD (the designed immediate-completion answer): short-
circuit 0x9ea52730's entry. Its own success path returns the timeout echo
('mov eax, [rbp-0x18]' = edi), so the designed instant answer is exactly
    mov eax, edi ; ret
The single caller (0x9e869395) ignores the return value; every print and
every subsequent counter init in the thunk body is preserved. 5-byte
in-place patch, no cave needed.
"""
import sys

KTEXT = 0x9E3F0000
IMG = "./wp21_kit/wp3_boot/kernel_raw.bin"

S = 0x9EA52730
OLD = bytes.fromhex("554889e553")            # push rbp; mov rbp,rsp; push rbx
NEW = bytes.fromhex("89f8c39090")            # mov eax,edi; ret; nop; nop

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

off = S - KTEXT
site = bytes(img[off:off+len(OLD)])
if site == NEW:
    print(f"site {S:#x} already patched (idempotent) — OK")
    sys.exit(0)
if site != OLD:
    print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)

img[off:off+len(NEW)] = NEW
open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP21-G16: hypervisor settle-wait short-circuit @0x{S:X} "
      f"(mov eax,edi; ret — the designed immediate completion)")
