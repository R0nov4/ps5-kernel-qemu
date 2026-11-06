#!/usr/bin/env python3
"""WP15 #5 — vm_dom block-array SEED (root fix for the whole checker family).

CONTEXT: FOUR checker functions deref [vm_dom[dom]+0x10] (the per-domain
2MB-block descriptor array, blocks of 0x50 bytes, index = (phys-base)>>21):
  A 0x9e945bf0  cmp dword [blk+0x38], 0x80   "block full?" (promotion)
  B 0x9e945bb0  cmp qword [blk+0x20], 1      "block empty?"
  C 0x9e945c30  mov  r8, [blk+0x20]          "take page from block list"
  D 0x9e945600  cmp qword [blk+0x20], 0     "block has objects?" (objq)
All read NULL on our cold boot (WP12 wiped dom0's live value; dom1..10 were
never non-NULL) -> crash 0x9e945c1f (CR2=0x38, fixed by the cave guards #2)
then crash 0x9e945629 (CR2=0x9da0 = NULL + 504*0x50 + 0x20 — block 504 =
phys [0x3F000000,0x3F200000) = OUR SEED AREA: the W1 vm_pages!).

FIX (systemic, subsumes the per-function guards): seed every domain's
block-array pointer with a DMAP zero region:
  [vm_dom[i] + 0x10] := DMAP(0x3F170000)   for i = 0..10
  (vm_dom @0xa197a3d0, stride 0x28, 11 entries — dom8/9 keep their live
   residue bases 0x44b600000/0x44f600000; our pages are dom 0, base 0)
A zero block array gives every reader the DESIGNED 'empty block' answer:
  [blk+0x20]=0 -> empty/none, [blk+0x38]=0 -> not full. Writers (block
  free-list population) land in the seed region harmlessly.
  Seed region [0x3F170000, 0x3F190000) = 128KB = 1024 blocks x 0x50 =
  2GB of phys coverage — inside the WP11 SMAP-reserved window, above the
  node chains (0x3F140000..0x3F170000), below the pool (0x3F200000+),
  never page-ified, DMAP-mapped (W8 built the [1GB,2GB) PD; WP14's pool
  uses DMAP up to 0x40000000).
The cave guards 25/26/27 stay as belt-and-braces (with the seed they take
their normal paths).
"""
import struct

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

VM_DOM = 0xA197A3D0
NDOM = 11
SEED = 0xFFFF8E773F170000        # DMAP(0x3F170000)

img = bytearray(open(IMG, "rb").read())

for i in range(NDOM):
    va = VM_DOM + i * 0x28 + 0x10
    off = va - KTEXT
    old = struct.unpack_from("<Q", img, off)[0]
    if old != 0:
        print(f"FAIL dom{i} +0x10 @{va:#x} = {old:#018x} (expected 0)")
        raise SystemExit(1)
    struct.pack_into("<Q", img, off, SEED)
    print(f"  dom{i}: [{va:#x}] := {SEED:#018x}")

open(IMG, "wb").write(img)
print("OK WP15#5: vm_dom block-array seed (11 domains -> DMAP(0x3F170000))")
