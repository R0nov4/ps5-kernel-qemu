#!/usr/bin/env python3
"""WP29 — find the dispatcher that reads the thunk tables at
0xa0fe76e8 / 0xa0943a18 (rip-relative refs in whole text)."""
import re, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

K = 0x9E3F0000
TEXT_HI = 0x9F780000
img = open("wp3_boot/kernel_raw.bin", "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

def at(va, n): return img[va - K: va - K + n]
def cstr(va, maxlen=56):
    out = bytearray(); off = va - K
    while len(out) < maxlen and 0 <= off < len(img):
        c = img[off + len(out)]
        if c == 0: break
        out.append(c)
    try: s = out.decode("ascii")
    except UnicodeDecodeError: return None
    return s if s and all(32 <= ord(ch) < 127 for ch in s) else None
def padding_run(va, n=8):
    b = at(va, n)
    return len(b) == n and all(c in (0xCC, 0x90) for c in b)
def prologue_back(va, w=0x1000):
    lo = max(K, va - w)
    idx = bytes(img).rfind(b"\x55\x48\x89\xe5", lo - K, va - K + 1)
    return K + idx if idx >= 0 else None

TARGETS = {0xA0FE76E8: "thunk 0x9e658db8 (0x9e823290)",
           0xA0943A18: "thunk 0x9e658ed8 (0x9e9e27f0)"}
# also table bases nearby (structs read at ± offsets)
SCAN = set()
for t in TARGETS:
    for off in range(-0x30, 0x30, 8):
        SCAN.add(t + off)

print("=== rip-relative refs to the thunk tables (whole text) ===")
hits = []
for m in re.finditer(rb"[\x48\x4c\x8d\x8b]", img[:TEXT_HI - K]):
    p = m.start()
    # quick check: lea/mov with rip-rel (opcode 8d/8b + modrm 05 pattern) — scan instruction window
    for ln in (6, 7, 8):
        if p + ln > len(img): continue
        chunk = img[p:p+ln]
        # try disasm
        ins = list(md.disasm(chunk, K + p))
        if not ins: continue
        i = ins[0]
        mm = re.search(r"rip\s*([+-])\s*(0x[0-9a-f]+)", i.op_str or "")
        if mm:
            rt = i.address + i.size + int(mm.group(2), 16) * (-1 if mm.group(1) == "-" else 1)
            if rt in SCAN:
                hits.append((i.address, rt, i.mnemonic, i.op_str))
        break

seen_fn = {}
for addr, rt, mn, ops in hits:
    W = prologue_back(addr)
    key = (W, rt)
    if key in seen_fn: continue
    seen_fn[key] = True
    print(f"  {addr:#x} (fn {W and hex(W)}): {mn} {ops}  -> table {rt:#x} ({TARGETS.get(rt, 'struct-neighborhood')})")
