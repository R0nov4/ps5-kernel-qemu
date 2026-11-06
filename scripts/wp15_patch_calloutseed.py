#!/usr/bin/env python3
"""WP15 #9 — per-CPU callout hash-table seed (crash 0x9ef8ade3, CR2=0xffffff800710ca78).

ROOT CAUSE (GDB-verified):
  The per-CPU callout array @0xa2174c40 (16 entries x 0x140: {name
  'callout'@+0x00, size-ish@+0x08, ...@+0xc8, hash-table@+0xd0}) carries
  LIVE-DUMP residue table pointers with the 0xffffff80........ prefix
  (0xffffff80070f4000, 0xffffff800712c000, ...) that WP12's DMAP wipe
  (needle 0xffff8e77) never matched. The callout insert path:
    0x9ef8add6  and eax, [0xa2179c44]       ; hash mask = 0x3fff (16384 buckets)
    0x9ef8addc  mov rcx, [r13 + 0xd0]       ; the residue table
    0x9ef8ade3  mov rcx, [rcx + rax*8]      ; <<< CRASH (unmapped live VA)
    0x9ef8ade7  mov [rbx], rcx              ; callout->next = bucket head
  (GDB: r12=r13=0xa2174c40 entry0, rcx=0xffffff80070f4000, rax=0x314f.)

FIX:
  - wipe entry0's +0xc8 residue (0xffffff8007000000 -> 0; entries 1..15
    are already 0 — the designed cold-boot value)
  - seed every entry's +0xd0 hash table with its own zero region:
      [0xa2174c40 + i*0x140 + 0xd0] := DMAP(0x23800000 + i*0x20000)
    16 x 128KB (0x20000 = 16384 buckets x 8) = 2MB inside the bucket2/3
    hole ([0x22225000, 0x26410000) — never page-ified, stays zero, above
    the WP15#6 bucket-array seed [0x23000000,0x23800000)). Zero buckets
    -> every callout insert takes the designed 'empty list' path; the
    subsequent links land in the hole harmlessly.
"""
import struct

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CALLOUT = 0xA2174C40
NENT = 16
TAB_BASE = 0x23800000            # phys, in the bucket2/3 hole
TAB_SZ = 0x20000                 # 16384 buckets x 8
DMAP = 0xFFFF8E7700000000

img = bytearray(open(IMG, "rb").read())

# entry0 +0xc8 residue -> 0
va = CALLOUT + 0xC8
off = va - KTEXT
old = struct.unpack_from("<Q", img, off)[0]
if old != 0xFFFFFF8007000000:
    print(f"FAIL entry0 +0xc8 @{va:#x} = {old:#018x}")
    raise SystemExit(1)
struct.pack_into("<Q", img, off, 0)
print(f"  entry0 +0xc8 wiped: {old:#018x} -> 0")

for i in range(NENT):
    va = CALLOUT + i * 0x140 + 0xD0
    off = va - KTEXT
    old = struct.unpack_from("<Q", img, off)[0]
    seed = DMAP + TAB_BASE + i * TAB_SZ
    if old == 0:
        print(f"  entry{i} +0xd0 already 0?? (unexpected)")
    struct.pack_into("<Q", img, off, seed)
    print(f"  entry{i}: [{va:#x}] {old:#018x} -> {seed:#018x}")

# range sanity: [0x23800000, 0x23800000+16*0x20000) must stay in the hole
end = TAB_BASE + NENT * TAB_SZ
assert end <= 0x26410000, f"table range overruns the hole: {end:#x}"
print(f"  table range [{TAB_BASE:#x}, {end:#x}) inside the bucket2/3 hole OK")

open(IMG, "wb").write(img)
print("OK WP15#9: callout hash-table seed (16 entries -> DMAP(0x23800000+))")
