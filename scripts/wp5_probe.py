#!/usr/bin/env python3
"""WP5 probe: read config byte 0xa1d0ae50 (page-layout mode), panic string
0x9f76cce4, canary residue 0xa1d0c310, and context hexdumps from the ELF."""
import struct

ELF = "./download/ps5_kernel_1360_reconstructed.elf"
T_VA, T_OFF, T_SZ = 0x9E3F0000, 0x1000, 0xCC0000
D_VA, D_OFF, D_SZ = 0x9F0B0000, 0xCC1000, 0x3174000
blob = open(ELF, "rb").read()

def va2img(va):
    lo = va & 0xFFFFFFFF
    if 0x9E3F0000 <= lo < 0x9F0B0000: return lo - 0x9E3F0000
    if 0x9F0B0000 <= lo < 0xA2224000: return 0xCC0000 + (lo - 0x9F0B0000)
    raise ValueError(hex(va))

def img_bytes(va, n):
    o = va2img(va)
    if o < 0xCC0000: return blob[T_OFF+o:T_OFF+o+n]
    return blob[D_OFF+(o-0xCC0000):D_OFF+(o-0xCC0000)+n]

def cstr(va, maxlen=200):
    b = img_bytes(va, maxlen)
    return b.split(b"\0")[0].decode("latin1", "replace")

# 1. the config byte at 0xa1d0ae50
b = img_bytes(0xA1D0AE50, 1)[0]
mode = b & 0x60
verdict = {0x20: "MODE 1 (OK, returns 1)", 0x40: "MODE 2 (OK, returns 2)"}.get(mode, "INVALID -> PANIC PATH 0x9eaca9be!")
print(f"[0xa1d0ae50] = 0x{b:02x}   & 0x60 = 0x{mode:02x}   => {verdict}")

# 2. second config byte (getter at 0x9eaca9f0)
b2 = img_bytes(0xA1D0AEF3, 1)[0]
print(f"[0xa1d0aef3] = 0x{b2:02x}")

# 3. panic string
print(f"panic fmt @0x9f76cce4: {cstr(0x9F76CCE4)!r}")

# 4. canary residue
can = struct.unpack("<Q", img_bytes(0xA1D0C310, 8))[0]
print(f"canary @0xa1d0c310 residue = 0x{can:016x}")

# 5. hexdump context around the config byte
for base, n in [(0xA1D0AE30, 0x40), (0xA1D0AED0, 0x40)]:
    d = img_bytes(base, n)
    print(f"\n@0x{base:x}:")
    for i in range(0, n, 16):
        row = d[i:i+16]
        print(f"  0x{base+i:x}: {row.hex(' ')}  {''.join(chr(c) if 32<=c<127 else '.' for c in row)}")

# 6. also dump the strings in .rodata near the panic fmt (often sibling messages)
print("\nnearby strings around 0x9f76cce4:")
for va in range(0x9F76CC60, 0x9F76CD80, 8):
    try:
        s = cstr(va, 80)
        if len(s) >= 8 and all(32 <= ord(c) < 127 for c in s[:8]):
            print(f"  0x{va:x}: {s!r}")
    except Exception:
        pass
