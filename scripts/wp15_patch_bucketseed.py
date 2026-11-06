#!/usr/bin/env python3
"""WP15 #6 — dom0 free-area bucket array SEED (crash 0x9ea05663, CR2=0x2e68e0).

ROOT CAUSE (GDB-verified):
  The dom0 free-area buckets @0xa1add9a0 (stride 0x28: {start_phys@+0,
  end_phys@+8, vm_page_array@+0x10, ...@+0x18, lock@+0x20}) lost their
  vm_page-array pointers: the live values (e.g. bucket3 =
  DMAP(0x5f25e328), phys in the WP12-wipe window [0x22225000,0x40000000))
  were wiped, and the boot's own re-allocation of the arrays goes through
  the kernel malloc which WP13's cave11 cleanly returns NULL from. The
  lookup function (0x9ea055b0, "vm_phys_find_page": bucket search by
  m->phys, then vm_page = [bucket+0x10] + pagenum*0x78, stride 0x78 =
  THE REAL vm_page SIZE) derefs the NULL array:
    0x9ea0565a  mov r15, [r12+0x10]          ; = 0
    0x9ea0565f  imul rax, rcx, 0x78          ; pagenum 25345 (seed-area page)
    0x9ea05663  movzx ecx, byte [r15+rax+0x68]  <<< CRASH CR2=0x2e68e0
  (caller chain: vm_page_startup loop -> 0x9ef7a678 -> 0x9ef790ac ->
   the lookup with a W1 vm_page whose phys = 0x3f0101e0 -> bucket3.)

FIX: seed every dom0 bucket's array pointer with a big zero region:
  [0xa1add9a0 + i*0x28 + 0x10] := DMAP(0x23000000)   for i = 0..7
  DMAP(0x23000000) lies in the 'hole' between bucket2 (ends 0x1e200000)
  and bucket3 (starts 0x26410000) — RAM the buckets do not cover, so it
  is never page-ified and stays zero. Coverage: [0x23000000, 0x23800000)
  = 8MB / 0x78 = 70k pagenums > the largest bucket span (bucket3 needs
  57989*0x78 = 7.15MB). Zero reads -> every lookup takes the designed
  'not found' mismatch path; any array fill the boot performs later
  lands in the same hole harmlessly. dom1..dom10 need nothing: their
  buckets are all start=end=0 (never match, never deref).
"""
import struct

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

BUCKETS = 0xA1ADD9A0            # dom0 free-area buckets (stride 0x28)
SEED    = 0xFFFF8E7723000000    # DMAP(0x23000000) — the bucket2/3 hole, 8MB+

img = bytearray(open(IMG, "rb").read())

for i in range(8):
    va = BUCKETS + i * 0x28 + 0x10
    off = va - KTEXT
    old = struct.unpack_from("<Q", img, off)[0]
    if old != 0:
        print(f"FAIL bucket{i} +0x10 @{va:#x} = {old:#018x} (expected 0)")
        raise SystemExit(1)
    struct.pack_into("<Q", img, off, SEED)
    start = struct.unpack_from("<Q", img, BUCKETS + i*0x28 - KTEXT)[0]
    end = struct.unpack_from("<Q", img, BUCKETS + i*0x28 + 8 - KTEXT)[0]
    print(f"  bucket{i} [{start:#x},{end:#x}): [{va:#x}] := {SEED:#018x}")

open(IMG, "wb").write(img)
print("OK WP15#6: dom0 bucket vm_page-array seed (8 buckets -> DMAP(0x23000000))")
