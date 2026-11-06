#!/usr/bin/env python3
"""WP17 #15 — the thread0 WITNESS head seed
          (crash 0xffffffff9e8b71bc, CR2=0x18 — the user's predicted
          'give thread0 a real witness page' systemic fix).

ROOT CAUSE (GDB wp17_gdb_c20):
  The mtx-acquire's witness bookkeeping (0x9e81d5df): when the tracked
  list is empty it takes thread0's witness head:
    r14 = [gs:[0] + 0x78]          ; thread0+0x78 — the WITNESS list head
    rdi = r14 + 0x18
    call 0x9e8b7190 (unlock)       ; <<< [thread0+0x78] = NULL -> rdi=0x18
                                   ;     -> 'mov rax,[rdi]' -> CR2=0x18
    [r14+0x78] = rbx               ; the list update
  The image's [thread0+0x78] = 0 (the pristine initial — the thread
  create-time witness allocation never ran on this boot); the LIVE dump
  holds the runtime object (0xffff8e7701759e00).

FIX — the systemic seed (the user's WP17 directive): point
  [thread0+0x78] at a pristine-zero writable page in the seed-area
  scratch gap: DMAP(0x3F1A0A00) (above the WP17#1 zone seed
  [0x3F1A0880,0x3F1A0998), below the malloc window @0x3F1A1000).
  The zero page: the lock word at +0x18 reads 0 -> the designed
  unowned-unlock path ('mov [r12],4' free + td_locks--) — the witness
  list updates write harmlessly into the page.
"""
import struct
import sys

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

TD0_WITNESS = 0xA19788D8                    # thread0 (0xa1978860) + 0x78
SEED_WITNESS = 0xFFFF8E773F1A0A00           # DMAP(0x3F1A0A00) — zero page

img = bytearray(open(IMG, "rb").read())

off = TD0_WITNESS - KTEXT
cur = struct.unpack_from("<Q", img, off)[0]
if cur == SEED_WITNESS:
    print(f"[thread0+0x78] already seeded -> {SEED_WITNESS:#x} (idempotent)")
elif cur == 0:
    print(f"[thread0+0x78]: 0 (never initialized) -> seeding {SEED_WITNESS:#x}")
else:
    print(f"WARN [thread0+0x78] unexpected {cur:#x} -> reseeding anyway")

img[off:off+8] = struct.pack("<Q", SEED_WITNESS)

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP17#15: thread0 witness head seed (the zero page @0x3F1A0A00)")
