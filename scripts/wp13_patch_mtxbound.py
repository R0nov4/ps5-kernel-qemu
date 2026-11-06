#!/usr/bin/env python3
"""WP13 fix #2 — mtx_lock flag-only lock words (crash 0x9e8b6c71, CR2=0x400).

Context: after randompid (SceSwapper), mtx_lock's adaptive-spin loop reads
[owner+0x400] with owner = lock_word & ~7 == 0 -> CR2 = 0x400 exactly.
Lock word is therefore in {5,6,7}: live-dump residue flag bits (RECURSED 1 /
CONTESTED 2 + free-state 4) with NO owner thread.

WP11's sanctioned pattern already force-acquires words 0..4 via CAS
('ja' @0x9e8b6a34 + NOP'd mov eax,4 so CAS expects rax = actual word).
This fix extends the fast-path bound 4 -> 0xF (cmp rax,4 -> cmp rax,0xF
@0x9e8b6a30, one byte) so ALL small non-owner words (0..0xF — free marker,
residue flags, never-init) CAS-acquire atomically. Real owned locks hold
canonical thread pointers (>> 0xF) and still take the slow path — no lock
stealing. Also preempts the word 8..0xF variant (would crash at 0x408).
"""
import sys

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SITE = 0x9e8b6a30
OLD = bytes.fromhex("4883f804")     # cmp rax, 4
NEW = bytes.fromhex("4883f80f")     # cmp rax, 0xf

img = bytearray(open(IMG, "rb").read())
off = SITE - KTEXT
cur = bytes(img[off:off + 4])
if cur != OLD:
    # tolerate the already-patched state for idempotent rebuilds
    if cur == NEW:
        print(f"already patched @ {SITE:#x} (cmp rax, 0xf)")
        sys.exit(0)
    print(f"FAIL @ {SITE:#x}: {cur.hex()} != {OLD.hex()}")
    sys.exit(1)

img[off:off + 4] = NEW
open(IMG, "wb").write(img)
print(f"OK mtx_lock fast-path bound 4 -> 0xf @ {SITE:#x}: {OLD.hex()} -> {NEW.hex()}")
print("   lock words 0..0xf now CAS-acquire (owner-less/residue semantics)")
