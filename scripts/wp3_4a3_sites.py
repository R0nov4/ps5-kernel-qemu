#!/usr/bin/env python3
"""WP3-4a v3: disassemble the 3 key crash sites + read strings."""
from capstone import *
img = open("./wp3_boot/kernel_raw.bin", "rb").read()
def va2img(va):
    lo = va & 0xFFFFFFFF
    if 0x9E3F0000 <= lo < 0x9F0B0000: return lo - 0x9E3F0000
    if 0x9F0B0000 <= lo < 0xA2224000: return 0xCC0000 + (lo - 0x9F0B0000)
    return None
def rd(va, n):
    o = va2img(va); return None if o is None else img[o:o+n]
def cstr(va, maxlen=100):
    b = rd(va, maxlen)
    if b is None: return None
    z = b.find(b"\x00"); s = b[:z if z >= 0 else maxlen]
    return s if all(32 <= c < 127 for c in s) else None
md = Cs(CS_ARCH_X86, CS_MODE_64)
def dis(va, back, fwd, mark=None):
    for i in md.disasm(rd(va - back, back + fwd), va - back):
        m = "   <<<< FAULT IP" if mark and i.address == mark else ""
        print(f"  {i.address:#x}: {i.bytes.hex():22s} {i.mnemonic:9s} {i.op_str}{m}")

print("=== EVENT 0 faulting instr: 0xffffffff9ec227c8 (CR2=0xc08, NULL+0xC08) ===")
dis(0x9EC227C8, 0x60, 0x20, mark=0x9EC227C8)
print("\n=== EVENT 0 RBX string 0x9f67b8ea ===")
print(f"  {cstr(0x9F67B8EA)!r}")

print("\n=== EVENT 1 faulting instr: 0xffffffff9ee30cc5 (CR2=RAX+0x10, wild ptr) ===")
dis(0x9EE30CC5, 0x60, 0x20, mark=0x9EE30CC5)

print("\n=== EVENT 2 #GP site: 0xffffffff9ea1d440 (the MSR #GP!) ===")
dis(0x9EA1D440, 0x70, 0x20, mark=0x9EA1D440)
print("\n=== EVENT 2 RSI/R14 string 0x9f756c1f ===")
print(f"  {cstr(0x9F756C1F)!r}")
# strings around it
for off in (-0x40, -0x20, 0x18, 0x30):
    s = cstr(0x9F756C1F + off)
    if s: print(f"  +{off:+#x}: {s!r}")

print("\n=== EVENT 3 #PF site: 0xffffffff9e64482c (inside stub region!) ===")
dis(0x9E64482C, 0x80, 0x20, mark=0x9E64482C)

print("\n=== EVENT 0 R10 = 0x9e89f525 (printf-region return addr?) ===")
dis(0x9E89F525, 0x30, 0x10)

print("\n=== what reads event-2 RBX = DMAP(0x17e6f80)? — .data ptr hunt ===")
# search .data for the qword 0xffff8e77017e6f80 (stale live pointer)
target = (0xFFFF8E77017E6F80).to_bytes(8, "little")
i = img.find(target)
while i != -1:
    va = (0x9F0B0000 + (i - 0xCC0000)) if i >= 0xCC0000 else (0x9E3F0000 + i)
    print(f"  found stale ptr 0xffff8e77017e6f80 at VA {va:#x}")
    i = img.find(target, i + 1)
target2 = (0xFFFF8E7701974000).to_bytes(8, "little")
i = img.find(target2)
while i != -1:
    va = (0x9F0B0000 + (i - 0xCC0000)) if i >= 0xCC0000 else (0x9E3F0000 + i)
    print(f"  found stale ptr 0xffff8e7701974000 at VA {va:#x}")
    i = img.find(target2, i + 1)
