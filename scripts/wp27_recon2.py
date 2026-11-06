#!/usr/bin/env python3
"""WP27 recon2 — fn 0x9e7e0650 full disasm + callers (full-text scan, thunks)."""
import re, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
img = open("wp3_boot/kernel_raw.bin", "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
TARGET = 0x9E7E0650
TEXT_END = 0x9F780000 - KTEXT

def at(va, n): return img[va - KTEXT: va - KTEXT + n]
def cstr(va, maxlen=48):
    out = bytearray(); off = va - KTEXT
    while len(out) < maxlen and 0 <= off < len(img):
        c = img[off + len(out)]
        if c == 0: break
        out.append(c)
    try: s = out.decode("ascii")
    except UnicodeDecodeError: return "<bin>"
    return s if s and all(32 <= ord(ch) < 127 for ch in s) else "<bin>"

def rip_target(i):
    m = re.search(r"rip\s*([+-])\s*(0x[0-9a-f]+)", i.op_str)
    if m: return i.address + i.size + int(m.group(2), 16) * (-1 if m.group(1) == "-" else 1)
    return None

def padding_run(va, n=8):
    b = at(va, n)
    return len(b) == n and all(c in (0xCC, 0x90) for c in b)

def disasm_fn(start, cap=0x600):
    out = []
    for i in md.disasm(at(start, cap), start):
        out.append(i)
        if padding_run(i.address + i.size, 8): break
    return out

print("=== fn 0x9e7e0650 (full) ===")
for i in disasm_fn(TARGET):
    rt = rip_target(i)
    note = f"   ; -> {cstr(rt)!r}" if rt and i.mnemonic == "lea" else ""
    print(f"  {i.address:#x}: {i.bytes.hex():<16} {i.mnemonic} {i.op_str}{note}")

def resolve_entry(f, hops=4):
    seen = set()
    while hops > 0 and f not in seen:
        seen.add(f); b = at(f, 5)
        if b[0:1] == b"\xe9":
            t = f + 5 + struct.unpack("<i", b[1:5])[0]
            if 0x9E3F0000 <= t < 0x9F780000: f = t; hops -= 1; continue
        break
    return f

print("=== callers of 0x9e7e0650 (full text) ===")
hits = []
for m in re.finditer(rb"[\xe8\xe9]", img[:TEXT_END]):
    p = m.start()
    rel = struct.unpack("<i", img[p+1:p+5])[0]
    if KTEXT + p + 5 + rel == TARGET:
        hits.append((KTEXT + p, "direct"))
    elif resolve_entry(KTEXT + p + 5 + rel) == TARGET:
        hits.append((KTEXT + p, "thunk"))
print(f"sites: {[(hex(h), k) for h, k in hits]}")

def prologue_back(va):
    lo = max(KTEXT, va - 0x800)
    idx = bytes(img).rfind(b"\x55\x48\x89\xe5", lo - KTEXT, va - KTEXT + 1)
    return KTEXT + idx if idx >= 0 else None

for site, kind in hits:
    W = prologue_back(site)
    fi = disasm_fn(W)
    idx = next(j for j, i in enumerate(fi) if i.address == site)
    print(f"--- caller fn {W:#x} ({kind}) call @ {site:#x} ---")
    for i in fi[max(0, idx-6):idx+3]:
        rt = rip_target(i)
        note = f"   ; -> {cstr(rt)!r}" if rt and i.mnemonic == "lea" else ""
        print(f"  {i.address:#x}: {i.mnemonic} {i.op_str}{note}")
