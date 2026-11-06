#!/usr/bin/env python3
"""WP20 G12 — THE HRTIMER + POLLING-TIMER NULL-PATH FAMILY  [NEW FRONTIER]
          [2 local in-place edits — each panic block becomes the fn's own
            designed early return]
          (panic 'hrtimer: initialize failed' / 'failed to find a polling
           timer hardware' — both after 'Device configuration finished.')

GUARD A — hrtimer_init (fmt 0x9F770CBF): the zone allocator 0x9f02d680
  answered NULL; the NULL branch (assert + vpanic + ud2) becomes the
  fn's own 'pop rbp; ret':
      0x9eeb793d  call 0x9ebe1950     ; the NULL branch head
      -> 5d c3 (pop rbp; ret) + 3 nops

GUARD B — the polling-timer init (fmt 0x9F71FE9E, line 27): the same
  allocator, same shape; the NULL branch becomes the fn's epilogue
  (add rsp,8; pop rbx; pop rbp; ret):
      0x9e704ea7  call 0x9ebe1950 ; lea rdi,[rip-0xc]  (12B window)
      -> 48 83 c4 08 ; 5b ; 5d ; c3 (add rsp,8; pop rbx; pop rbp; ret)
"""
import sys

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

def inplace(S, OLD, NEW, label):
    off = S - KTEXT
    site = bytes(img[off:off+len(NEW)])
    if site == NEW:
        print(f"OK {label}: already guarded (idempotent) @ {S:#x}")
        return
    if site != OLD:
        print(f"FAIL {label} {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
    img[off:off+len(NEW)] = NEW
    print(f"OK {label}: {OLD.hex()} -> {NEW.hex()} @ {S:#x}")

# GUARD A — hrtimer NULL-path early return
inplace(0x9EEB793D,
        bytes.fromhex("e80ea0d2ff"),                    # call 0x9ebe1950
        bytes.fromhex("5dc3" + "909090"),               # pop rbp; ret; nops
        "hrtimer NULL-path early return")

# GUARD B — polling-timer NULL-path early return
inplace(0x9E704EA7,
        bytes.fromhex("e8a4ca4d00" + "488d3df4ffffff"), # call + lea rdi,[rip-0xc]
        bytes.fromhex("4883c408" + "5b" + "5d" + "c3" + "90" * 5),
        "polling-timer NULL-path early return")

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print("OK WP20-G12: hrtimer + polling-timer NULL-path family (2 guards)")
