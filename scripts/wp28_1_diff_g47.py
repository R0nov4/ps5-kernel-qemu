#!/usr/bin/env python3
"""WP28 step 1: recover the G47 patch bytes by diffing the user's G47-only kernel vs WP26 output."""
import hashlib

WP26 = './wp26_stage/wp3_boot/kernel_raw.bin'      # a822c626...
G47  = './wp28_stage/wp3_boot/kernel_raw.bin'      # user's G47-only build

BASE = 0x9E3F0000   # va -> file_off = va - BASE

def load(p):
    with open(p, 'rb') as f:
        d = f.read()
    print(f"{p}: {len(d)} bytes, md5={hashlib.md5(d).hexdigest()}")
    return d

a = load(WP26)
b = load(G47)
assert len(a) == len(b) == 65224704, 'size mismatch'

# find diff ranges
diffs = []
i = 0
n = len(a)
while i < n:
    if a[i] != b[i]:
        j = i
        while j < n and a[j] != b[j]:
            j += 1
        diffs.append((i, j))
        i = j
    else:
        i += 1

print(f"\n{len(diffs)} diff ranges:")
for (s, e) in diffs:
    va_s, va_e = BASE + s, BASE + e
    print(f"  file 0x{s:08X}..0x{e:08X}  va 0x{va_s:08X}..0x{va_e:08X}  len {e-s}")
    print(f"    WP26 : {a[s:e].hex(' ')}")
    print(f"    G47  : {b[s:e].hex(' ')}")
