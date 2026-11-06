#!/usr/bin/env python3
"""WP26 recon — verify G45 targets, slot space, sysinit queue position."""
import hashlib, sys

KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"
img = open(IMG, "rb").read()
h = hashlib.md5(img).hexdigest()
print(f"md5: {h}  {'OK' if h == '5d438a939e327950884e8e97289d18a6' else 'MISMATCH!'}")
assert h == "5d438a939e327950884e8e97289d18a6"

def at(va, n):
    return img[va - KTEXT: va - KTEXT + n]

# --- G45 targets ---
jne = at(0x9E9EA94F, 2)
print(f"jne @0x9e9ea94f: {jne.hex()} (want 756a)")
epi = at(0x9E9EA9B4, 7)
print(f"epilogue @0x9e9ea9b4: {epi.hex()} (want 4883c4285b5dc3)")
pcall = at(0x9E9EA9DA, 5)
print(f"panic call @0x9e9ea9da: {pcall.hex()} (want e831006a00 -> 0x9f08aa10)")

# --- G43 hook in place (fn 0x9e937f60, site 0x9e9380c7 -> slot 0x9E404E80) ---
g43 = at(0x9E9380C7, 5)
rel = (0x9E404E80 - 0x9E9380CC) & 0xFFFFFFFF
print(f"G43 site @0x9e9380c7: {g43.hex()} (want e9 {rel.to_bytes(4,'little').hex()})")

# --- slot space: CC run from 0x9E405B00 ---
run, va = 0, 0x9E405B00
while at(va + run, 1) == b"\xcc":
    run += 1
print(f"CC run from 0x9E405B00: {run:#x} bytes = {run // 0x80} slots (0x80 each)")

# --- sysinit queue around the frontier ---
SET_LO, SET_HI = 0x9FE51FB0, 0x9FE55488
import struct
def slot(k):
    ptr = struct.unpack("<Q", at(SET_LO + 8 * k, 8))[0] & 0xFFFFFFFF
    if not (0x9FE73EC0 <= ptr < 0xA0FF9670) or ptr == 0:
        return k, ptr, None, None, None
    sub, order = struct.unpack("<II", at(ptr, 8))
    func = struct.unpack("<Q", at(ptr + 8, 8))[0]
    return k, ptr, sub, order, func

print("--- sysinit slots 1182..1190 ---")
for k in range(1182, 1191):
    k, ptr, sub, order, func = slot(k)
    if sub is None:
        print(f"  #{k}: struct {ptr:#x} (out of case0 range — dummy/zero)")
    else:
        print(f"  #{k}: struct {ptr:#x} sub={sub} order={order:#x} func={func:#x}")

# --- which slot's tree contains the crossmp fn 0x9e9ea8f0? ---
hits = []
for k in range(1185, 1340):
    k, ptr, sub, order, func = slot(k)
    if sub is not None and func in (0x9E9EA8F0,):
        hits.append((k, func))
print(f"direct handler 0x9e9ea8f0 at slots: {hits}")
