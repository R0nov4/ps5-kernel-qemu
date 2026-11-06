#!/usr/bin/env python3
"""WP29 dissection — the two suspects of the #1295 livelock.
A. malloc small path + cave50 (0x9e401200) + tail je 0x9eff8d21
B. caller 0x9e823290 (ret addr 0x9e8232a3) — retry on NULL?
C. caller 0x9e9e27f0
D. who calls 0x9e823290 (upward chain of stage #1295)
"""
import re, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

K = 0x9E3F0000
TEXT_HI = 0x9F780000
img = open("wp3_boot/kernel_raw.bin", "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

def at(va, n): return img[va - K: va - K + n]
def cstr(va, maxlen=64):
    out = bytearray(); off = va - K
    while len(out) < maxlen and 0 <= off < len(img):
        c = img[off + len(out)]
        if c == 0: break
        out.append(c)
    try: s = out.decode("ascii")
    except UnicodeDecodeError: return None
    return s if s and all(32 <= ord(ch) < 127 for ch in s) else None
def resolve(f, h=6):
    seen = set()
    while h > 0 and f not in seen:
        seen.add(f); b = at(f, 5)
        if b[0:1] == b"\xe9":
            t = f + 5 + struct.unpack("<i", b[1:5])[0]
            if K <= t < TEXT_HI: f = t; h -= 1; continue
        break
    return f
def padding_run(va, n=8):
    b = at(va, n)
    return len(b) == n and all(c in (0xCC, 0x90) for c in b)
def dis(start, cap, label, stop_at_padding=True):
    print(f"\n=== {label} ===")
    for i in md.disasm(at(start, cap), start):
        note = ""
        m = re.search(r"rip\s*([+-])\s*(0x[0-9a-f]+)", i.op_str)
        if m:
            rt = i.address + i.size + int(m.group(2), 16) * (-1 if m.group(1) == "-" else 1)
            s = cstr(rt)
            note = f"  ; rip->{rt:#x}" + (f" {s!r}" if s else "")
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
            try: note += f"  ; {i.mnemonic}->{resolve(int(i.op_str,16)):#x}"
            except Exception: pass
        print(f"  {i.address:#x}: {i.bytes.hex():<22} {i.mnemonic} {i.op_str}{note}")
        if stop_at_padding and padding_run(i.address + i.size, 8): break

# A. malloc small path + cave50 + tail
dis(0x9EE30B80, 0x30, "A1. malloc small path 0x9ee30b80 (cave11?)")
dis(0x9E401200, 0x90, "A2. cave50 0x9e401200 (full)")
dis(0x9EFF8D10, 0x98, "A3. malloc tail 0x9eff8d10..0x9eff8da8 (ret)")
# B. caller 0x9e823290
dis(0x9E823290, 0x280, "B. caller 0x9e823290 (full — retry on NULL?)")
# C. other caller 0x9e9e27f0
dis(0x9E9E27F0, 0x180, "C. caller 0x9e9e27f0 (full)")

# D. who calls 0x9e823290 / 0x9e9e27f0 (direct or thunk)
print("\n=== D. callers (full text) ===")
for tgt in (0x9E823290, 0x9E9E27F0):
    hits = []
    for m in re.finditer(rb"[\xe8\xe9]", img[:TEXT_HI - K]):
        p = m.start()
        t = K + p + 5 + struct.unpack("<i", img[p+1:p+5])[0]
        if t == tgt or (K <= t < TEXT_HI and at(t, 1)[:1] == b"\xe9" and resolve(t) == tgt):
            hits.append(K + p)
    print(f"callers of {tgt:#x}: {[hex(h) for h in hits]}")
    for h in hits:
        lo = max(K, h - 0x800)
        idx = bytes(img).rfind(b"\x55\x48\x89\xe5", lo - K, h - K + 1)
        W = K + idx if idx >= 0 else 0
        # context lines
        ctx = []
        for i in md.disasm(at(max(h - 0x20, K), 0x28), max(h - 0x20, K)):
            ctx.append(f"{i.mnemonic} {i.op_str}")
        print(f"  site {h:#x} in fn {W:#x}: ... {'; '.join(ctx[-5:])}")
