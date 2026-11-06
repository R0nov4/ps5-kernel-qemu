#!/usr/bin/env python3
"""WP29 v2 — pad-aware linear disasm (restart at padding), full rip-refmap.
Then: domain-loop callers (SLIST of domains at 0x9fe51fb0?), queue refs."""
import re, struct, sys
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
def prologue_back(va, w=0x1000):
    lo = max(K, va - w)
    idx = bytes(img).rfind(b"\x55\x48\x89\xe5", lo - K, va - K + 1)
    return K + idx if idx >= 0 else None

print("[*] pad-aware linear disasm ...", file=sys.stderr)
refmap, callmap = {}, {}
n_ins = 0
pos = 0
limit = TEXT_HI - K
while pos < limit:
    last_end = pos
    got = False
    for i in md.disasm(memoryview(img)[pos:limit], K + pos):
        n_ins += 1
        got = True
        last_end = (i.address + i.size) - K
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
        # skip padding runs between functions
        if last_end + 8 <= limit and all(c in (0xCC, 0x90) for c in img[last_end:last_end+8]):
            last_end += 8
            while last_end + 8 <= limit and all(c in (0xCC, 0x90) for c in img[last_end:last_end+8]):
                last_end += 8
            break
    pos = last_end if got else pos + 1
print(f"[*] {n_ins} insns, {len(refmap)} rip targets, {len(callmap)} call targets", file=sys.stderr)

def refs_to(t, label, maxn=10):
    rs = refmap.get(t, [])
    print(f"\n=== {label} ({t:#x}) — {len(rs)} refs ===")
    for site, mn, ops in rs[:maxn]:
        W = prologue_back(site)
        print(f"  {site:#x} (fn {W and hex(W)}): {mn} {ops}")

# A. dyn-sysinit queue + walk globals
for t, lab in [(0xA1978198, "dyn-queue head"), (0xA19781A0, "list tail marker"),
               (0xA19781A8, "list end"), (0xA19781B0, "queue tail")]:
    refs_to(t, lab)

# B. domain-struct zones
for zone, lo, hi in [("zone A", 0xA0FE7600, 0xA0FE7780), ("zone B", 0xA0943980, 0xA0943AC0)]:
    print(f"\n=== refs into {zone} ===")
    for t in sorted(refmap):
        if lo <= t < hi:
            print(f"  target {t:#x}: {len(refmap[t])} refs")
            for site, mn, ops in refmap[t][:6]:
                print(f"    {site:#x} (fn {prologue_back(site) and hex(prologue_back(site))}): {mn} {ops}")

# C. the domain LIST head — SLIST at 0x9fe51fb0? check refs to the 'domains' global
# the walker filter loop at 0x9e926250 uses lea esi->[0x9fe51fb0] — that's the static
# sysinit SET start. Also find the 'domains' SLIST head by refs to 0xa0fe76a0 zone bases:
for t in (0xA0FE76A0, 0xA09439D0, 0xA0FE6E00, 0xA0943250):
    refs_to(t, f"struct/table base {t:#x}")

import json
json.dump({hex(k): [[hex(s), m, o] for s, m, o in v][:60] for k, v in refmap.items()
           if 0x9FE00000 <= k < 0xA2200000}, open("wp29_refmap.json", "w"))
print("\nsaved wp29_refmap.json")
