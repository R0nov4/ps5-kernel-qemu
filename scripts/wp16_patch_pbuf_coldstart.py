#!/usr/bin/env python3
"""WP16 #9 — pbuf/bufwait list cold start (crash 0x9e84d990 CR2=0xffffff8006e496d8 W).

ROOT CAUSE (GDB):
  The buffer-IO SYSINIT ('bufwait'/'pbuf mutex' strings) builds the pbuf
  object list: the loop head reads the LIST HEAD global [0xa190b808] =
  0xffffff8006e495f0 — LIVE-RESIDUE from the original console's DMAP
  (the 0xffffff80 prefix — WP12's wipe needle was 0xffff8e77, this
  family was never touched) -> 'mov [rax+0xe8], r15' @0x9e84d990 writes
  the back-link through the unmapped residue pointer -> panic.
  The designed NULL check exists right there ('test rax,rax;
  je 0x9e84d920' @0x9e84d98b): a NULL head = an EMPTY list = the cold
  boot case — each iteration then creates its fresh object inside the
  array (r15-0xe0) and links it.

FIX: wipe the residue list head + tail in the image .data:
    [0xa190b808] := 0   (the list head)
    [0xa190b810] := 0   (the list tail)
  -> the loop takes the designed empty-list path and builds the whole
  list from the array itself.
"""
import struct

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

img = bytearray(open(IMG, "rb").read())

for addr, name in [(0xA190B808, "pbuf list head"), (0xA190B810, "pbuf list tail")]:
    off = addr - KTEXT
    old = struct.unpack_from("<Q", img, off)[0]
    if old == 0:
        print(f"[{addr:#x}] ({name}) already 0")
        continue
    if (old >> 32) != 0xFFFFFF80 and (old >> 32) != 0xFFFFFFFF:
        print(f"FAIL [{addr:#x}] ({name}) = {old:#018x} — unexpected value")
        raise SystemExit(1)
    struct.pack_into("<Q", img, off, 0)
    print(f"[{addr:#x}] ({name}): {old:#018x} -> 0")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP16#9: pbuf/bufwait list cold start")
