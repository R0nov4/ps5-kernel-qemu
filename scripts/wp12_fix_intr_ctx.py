#!/usr/bin/env python3
"""WP12 fix #7 — relocate the 'intr sources' registry context pointers.

After the DMAP-low wipe, the intr-subsystem context at 0xa1950a90-ish lost
three pointers (pristine: DMAP(0x1001FE0/0x1003D18/0x1002D28) — the live
machine's intr_event objects at phys ~16.8MB).  The stage function
0x9ebd7be0 ('intr sources', name @0x9f67bc23) dereferences
[0xA1950AB8]+0x20 unconditionally -> CR2=0x20 @0x9ebd7c06.

Cold-boot semantics: an empty/unconfigured registry = zeroed page.
Seed-area page allocation ledger (phys):
    0x3F000008  list-tail (W6)
    0x3F001000  bitmap   (W4)
    0x3F00A000  mDBG state (fix #6, 0x1100 bytes)
    0x3F009000  intr ctx #1  [0xa1950aa8]
    0x3F00C000  intr ctx #2  [0xa1950ab0]
    0x3F00D000  intr ctx #3  [0xa1950ab8]
    0x3F00F000  PD (W8)  |  0x3F010000+ bump objects (W1)
"""
import struct

KTEXT = 0x9E3F0000
DMAP = 0xFFFF8E7700000000
KIT = "./kit_build/wp3_boot/kernel_raw.bin"

RELOC = {
    0xA1950AA8: DMAP + 0x3F009000,
    0xA1950AB0: DMAP + 0x3F00C000,
    0xA1950AB8: DMAP + 0x3F00D000,
}

kit = bytearray(open(KIT, "rb").read())
for va, new in RELOC.items():
    off = va - KTEXT
    cur = struct.unpack_from("<Q", kit, off)[0]
    if cur == new:
        print(f"SKIP {va:#x} (already relocated)")
        continue
    if cur != 0:
        print(f"FAIL {va:#x}: expected 0 (wiped), found {cur:#018x}")
        raise SystemExit(1)
    struct.pack_into("<Q", kit, off, new)
    print(f"[{va:#x}] = {new:#018x}  (DMAP phys {new - DMAP:#x}, fresh-zero seed page)")

open(KIT, "wb").write(kit)
print("intr sources context relocated to zero pages ('unconfigured' cold state)")
