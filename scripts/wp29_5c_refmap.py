#!/usr/bin/env python3
"""WP29 v3 — function-at-a-time disasm (prologue-marker enumeration):
fast full-text rip-refmap + callmap."""
import re, struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

K = 0x9E3F0000
TEXT_HI = 0x9F780000
img = open("wp3_boot/kernel_raw.bin", "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
bimg = bytes(img)

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
def prologue_back(va, w=0x1000):
    lo = max(K, va - w)
    idx = bimg.rfind(b"\x55\x48\x89\xe5", lo - K, va - K + 1)
    return K + idx if idx >= 0 else None

print("[*] enumerating function starts ...", file=sys.stderr)
starts = []
p = bimg.find(b"\x55\x48\x89\xe5")
while p >= 0 and p < TEXT_HI - K:
    # a function start: preceded by padding (cc/90 run) or 0
    q = p
    run = 0
    while q > 0 and bimg[q-1] in (0xCC, 0x90) and run < 8:
        q -= 1; run += 1
    if run >= 3 or p == 0:
        starts.append(p)
    p = bimg.find(b"\x55\x48\x89\xe5", p + 1)
print(f"[*] {len(starts)} candidate fn starts", file=sys.stderr)

refmap, callmap = {}, {}
n_ins = 0
n_fn = 0
for s in starts:
    n_fn += 1
    cap = min(0x3000, TEXT_HI - K - s)
    end = s
    for i in md.disasm(memoryview(img)[s:s+cap], K + s):
        n_ins += 1
        end = (i.address + i.size) - K
        ops = i.op_str or ""
        if "rip" in ops:
            m = re.search(r"rip\s*([+-])\s*(0x[0-9a-f]+)", ops)
            if m:
                rt = i.address + i.size + int(m.group(2), 16) * (-1 if m.group(1) == "-" else 1)
                refmap.setdefault(rt, []).append((i.address, i.mnemonic, ops))
        if i.mnemonic in ("call", "jmp") and ops.startswith("0x"):
            try:
                t = int(ops, 16)
                if K <= t < TEXT_HI:
                    callmap.setdefault(t, []).append(i.address)
            except ValueError: pass
        if end + 8 <= s + cap and all(c in (0xCC, 0x90) for c in img[end:end+8]):
            break
print(f"[*] {n_fn} fns, {n_ins} insns, {len(refmap)} rip targets, {len(callmap)} call tgts", file=sys.stderr)

def refs_to(t, label, maxn=12):
    rs = refmap.get(t, [])
    print(f"\n=== {label} ({t:#x}) — {len(rs)} refs ===")
    for site, mn, ops in rs[:maxn]:
        W = prologue_back(site)
        print(f"  {site:#x} (fn {W and hex(W)}): {mn} {ops}")

for t, lab in [(0xA1978198, "dyn-queue head"), (0xA19781A0, "list tail marker"),
               (0xA19781A8, "list end"), (0xA19781B0, "queue tail")]:
    refs_to(t, lab)

for zone, lo, hi in [("zoneA", 0xA0FE7600, 0xA0FE7780), ("zoneB", 0xA0943980, 0xA0943AC0)]:
    print(f"\n=== refs into {zone} ===")
    for t in sorted(refmap):
        if lo <= t < hi:
            print(f"  target {t:#x}: {len(refmap[t])} refs")
            for site, mn, ops in refmap[t][:6]:
                print(f"    {site:#x} (fn {prologue_back(site) and hex(prologue_back(site))}): {mn} {ops}")

for t in (0xA0FE76A0, 0xA09439D0, 0xA0FE6E00, 0xA0943250, 0xA0FE76A8, 0xA09439D8):
    refs_to(t, f"table base {t:#x}")

import json
json.dump({hex(k): [[hex(s), m, o] for s, m, o in v][:60] for k, v in refmap.items()},
          open("wp29_refmap.json", "w"))
json.dump({hex(k): [hex(s) for s in v][:60] for k, v in callmap.items()},
          open("wp29_callmap.json", "w"))
print("\nsaved wp29_refmap.json / wp29_callmap.json")
