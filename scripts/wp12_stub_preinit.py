#!/usr/bin/env python3
"""WP12 contingency — stub the stage-48 PREINIT_POOL->UMA conversion.

If the boot still crashes inside the conversion (empty 'UMA Kegs' 0xa18ead40 /
'UMA Zones' 0xa18eaf40 static templates), the user-sanctioned shortcut is to
make the converter return immediately: in the live dump the UMA structures are
ALREADY built in .data — the intermediate conversion stage is a redundant
re-execution and can be stubbed.

Stub: 0x9ebd7b40 (fn8, the sysinit entry func) := 31 c0 c3 90
      (xor eax, eax ; ret ; nop)
mi_startup then stamps entry DONE and proceeds to stage 49+.

Usage:  python3 wp12_stub_preinit.py [--fn6]
        --fn6 additionally stubs fn6 0x9e829770 (deeper converter).
"""
import sys

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SITES = [
    (0x9EBD7B40, bytes.fromhex("554889e5"), "fn8 stage-48 PREINIT_POOL converter"),
    (0x9E829770, bytes.fromhex("554889e5"), "fn6 pool->UMA deep converter"),
]

STUB = bytes.fromhex("31c0c390")   # xor eax,eax ; ret ; nop

img = bytearray(open(IMG, "rb").read())
do_fn6 = "--fn6" in sys.argv

for va, expect, label in SITES:
    if label.startswith("fn6") and not do_fn6:
        continue
    off = va - KTEXT
    cur = bytes(img[off:off + 5])
    if cur[:4] == STUB[:4]:
        print(f"SKIP {label} @ {va:#x}: already stubbed")
        continue
    if cur[:4] != expect[:4]:
        print(f"FAIL {label} @ {va:#x}: expected {expect[:4].hex()}, found {cur[:4].hex()}")
        sys.exit(1)
    img[off:off + 4] = STUB
    print(f"OK stubbed {label} @ {va:#x}: {expect.hex()} -> {STUB.hex()}")

open(IMG, "wb").write(img)
print("stage-48 conversion stubbed; mi_startup will stamp it DONE and advance")
