#!/usr/bin/env python3
"""WP12 fix #6 — relocate the mDBG state base pointer to fresh zero memory.

The DMAP-low residue wipe (fix #4) NULLed [0xA1FDF3C0] (pristine value
DMAP(0x1974000) — the live machine's mDBG state buffer).  But unlike queue
residue, this global is a STATE BUFFER the code writes unconditionally:
  0x9ee31090: mov rax,[0xA1FDF3C0]; mov [rax+0x1088],rdi; ...
-> rax=NULL -> write to 0x1088 (trap 12, primary crash after the sysctl stage).

Fix: point it at a fresh-zero seed-area page.  Layout in the seed area
(phys): list-tail 0x3F000008, bitmap 0x3F001000, PD 0x3F00F000,
bump objects 0x3F010000+.  Free & zero at boot: [0x3F003000, 0x3F00F000).
State struct needs >= 0x1090 bytes -> use 0x3F00A000 (20KB below the PD).
Cold-boot semantics: zeroed state = "no dumps configured".
"""
import struct

KTEXT = 0x9E3F0000
DMAP = 0xFFFF8E7700000000
KIT = "./kit_build/wp3_boot/kernel_raw.bin"
VA = 0xA1FDF3C0
NEW = DMAP + 0x3F00A000          # phys 0x3F00A000, fresh-zero seed page

kit = bytearray(open(KIT, "rb").read())
off = VA - KTEXT
cur = struct.unpack_from("<Q", kit, off)[0]
print(f"[{VA:#x}] current = {cur:#018x}")
if cur != 0:
    if cur == NEW:
        print("SKIP: already relocated")
        raise SystemExit(0)
    print(f"FAIL: expected 0 (wiped), found {cur:#018x}")
    raise SystemExit(1)

struct.pack_into("<Q", kit, off, NEW)
open(KIT, "wb").write(kit)
print(f"[{VA:#x}] = {NEW:#018x}  (DMAP phys 0x3F00A000, fresh-zero seed page)")
print("mDBG state base relocated; setter 0x9ee31090 now writes a valid buffer")
