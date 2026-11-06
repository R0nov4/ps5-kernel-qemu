#!/usr/bin/env python3
"""wp9_patch_trampoline.py — WP9 trampoline.elf patches (recreated in WP11).

1. NOP the two rsdp_scan() calls so QEMU's real RSDP (phys 0xF52B0) survives
   with its 'RSD PTR ' signature intact — the kernel gets it via the static
   [0xA1D93840] = 0xF52B0 image patch (W10).
   call sites: VA 0x103E8D / 0x103E9C  -> file offsets 0x4E8D / 0x4E9C
2. Verify the conslog gate patch-table entry ([0xa1926628]) still writes 0
   (the WP7 kit already has new==0 — no change needed).
"""
import struct
import sys

ELF = "./kit_build/wp3_boot/trampoline.elf"


def main():
    elf = bytearray(open(ELF, "rb").read())

    sites = [
        (0x4E8D, bytes.fromhex("e86c010000")),
        (0x4E9C, bytes.fromhex("e85d010000")),
    ]
    for fo, expect in sites:
        cur = bytes(elf[fo:fo + 5])
        if cur != expect:
            print(f"FAIL call site @file {fo:#x}: expected {expect.hex()}, found {cur.hex()}")
            sys.exit(1)
        elf[fo:fo + 5] = b"\x90" * 5
        print(f"OK   rsdp_scan call @file {fo:#x}: {cur.hex()} -> 9090909090")

    # gate verification (baked patch_table): entry off=0x03536628 len=8 new=0
    first = struct.pack("<II", 0x00C16A19, 3) + bytes([15, 1, 217]) + bytes([49, 192, 144])
    pos = bytes(elf).find(first)
    assert pos >= 0, "patch_table not found"
    p = pos
    gate_ok = False
    for n in range(676):
        off, ln = struct.unpack_from("<II", elf, p)
        expect = bytes(elf[p + 8:p + 8 + ln])
        new = bytes(elf[p + 8 + ln:p + 8 + 2 * ln])
        if off == 0x03536628:
            print(f"gate entry: off={off:#x} len={ln} expect={expect.hex()} new={new.hex()}")
            gate_ok = (new == bytes(ln))
            break
        p += 8 + 2 * ln
    if not gate_ok:
        print("FAIL: conslog gate new value != 0")
        sys.exit(1)
    print("gate OK: conslog gate [0xa1926628] := 0 already baked")

    open(ELF, "wb").write(elf)
    print(f"patched -> {ELF}")


if __name__ == "__main__":
    main()
