#!/usr/bin/env python3
"""WP5g: find absolute imm32 refs to the SMP panic strings."""
import struct
blob = open('./download/ps5_kernel_1360_reconstructed.elf', 'rb').read()
raw = blob[0x1000:0x1000+0xCC0000] + blob[0xCC1000:0xCC1000+0x3174000]
T_VA, T_SZ = 0x9E3F0000, 0xCC0000
text = raw[:T_SZ]
for name, va in [('smp_targeted_str', 0x9f675587), ('int_disabled_str', 0x9f68fac0),
                 ('timeout_str', 0x9f752e2f)]:
    imm = struct.pack('<I', va)
    for regop, rn in ((0xbe, 'esi'), (0xbf, 'edi')):
        pat = bytes([regop]) + imm
        i = 0
        while True:
            j = text.find(pat, i)
            if j < 0:
                break
            print(f"{name}: mov ${hex(va)},%{rn} at {hex(T_VA+j)}")
            i = j + 1
