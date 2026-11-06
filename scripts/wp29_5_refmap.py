#!/usr/bin/env python3
"""WP29 — linear disasm of whole text; map rip-relative targets -> sites.
Then query: the dynamic-sysinit queue globals (0xa1978198/0xa19781a0/
0xa19781a8/0xa19781b0), the sysinit-q mtx (0xa0fec080), and the static
entry structs holding the rib thunks (0xa0fe76xx, 0xa0943axx)."""
import re, struct, sys, json
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
def padding_run(va, n=8):
    b = at(va, n)
    return len(b) == n and all(c in (0xCC, 0x90) for c in b)

print("[*] linear disasm 0x9e3f0000..0x9f780000 ...", file=sys.stderr)
refmap = {}          # target -> [(site, mn, ops)]
callmap = {}         # direct call target -> [sites]
n_ins = 0
for i in md.disasm(img[:TEXT_HI - K], K):
    n_ins += 1
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
        except ValueError:
            pass
print(f"[*] {n_ins} insns, {len(refmap)} rip targets", file=sys.stderr)

def show_target(t, label, ctx=6):
    print(f"\n=== {label} ({t:#x}) — {len(refmap.get(t, []))} refs ===")
    for site, mn, ops in refmap.get(t, []):
        W = prologue_back(site)
        # local context
        loc = []
        p = site
        for k in range(ctx):
            back = list(md.disasm(at(p - 0 if k == 0 else 0, 0) or b"", p))  # placeholder
        print(f"  {site:#x} (fn {W and hex(W)}): {mn} {ops}")

def dump_struct(base, n, label):
    print(f"\n=== {label}: struct dump {base:#x}+{n} ===")
    for off in range(0, n, 8):
        q = struct.unpack("<Q", at(base + off, 8))[0] & 0xFFFFFFFF
        s = cstr(q) if 0x9E3F0000 <= q < 0xA1000000 else None
        two = struct.unpack("<II", at(base + off, 8))
        print(f"  +{off:#04x}: {q:#010x}  ({two[0]:#x},{two[1]:#x})" + (f"  str={s!r}" if s else ""))

# A. the queue globals
for t, lab in [(0xA1978198, "dyn-queue head"), (0xA19781A0, "list tail marker"),
               (0xA19781A8, "list end"), (0xA19781B0, "queue tail"),
               (0xA0FEC080, "sysinit q mtx/obj")]:
    show_target(t, lab)

# B. the entry structs (wide window: find all refs into the struct zones)
print("\n=== refs into 0xa0fe7600..0xa0fe7780 ===")
for t in sorted(refmap):
    if 0xA0FE7600 <= t < 0xA0FE7780:
        print(f"  target {t:#x}: {len(refmap[t])} refs")
        for site, mn, ops in refmap[t][:8]:
            W = prologue_back(site)
            print(f"    {site:#x} (fn {W and hex(W)}): {mn} {ops}")
print("\n=== refs into 0xa0943980..0xa0943ac0 ===")
for t in sorted(refmap):
    if 0xA0943980 <= t < 0xA0943AC0:
        print(f"  target {t:#x}: {len(refmap[t])} refs")
        for site, mn, ops in refmap[t][:8]:
            W = prologue_back(site)
            print(f"    {site:#x} (fn {W and hex(W)}): {mn} {ops}")

# C. struct dumps
dump_struct(0xA0FE7680, 0x100, "rib-entry zone A (0xa0fe7680)")
dump_struct(0xA0943980, 0x100, "rib-entry zone B (0xa0943980)")

# save the refmap for later queries
with open("wp29_refmap.json", "w") as f:
    json.dump({hex(k): [[hex(s), m, o] for s, m, o in v][:40]
               for k, v in refmap.items() if 0x9FE00000 <= k < 0xA2200000}, f)
print("\nsaved wp29_refmap.json (data-section targets)")
