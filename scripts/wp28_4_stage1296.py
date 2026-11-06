#!/usr/bin/env python3
"""WP28 — full disasm of stage #1296 handler 0x9edf4130 (canvasmap) + its callees."""
import re, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT  = 0x9E3F0000
TEXT_HI= 0x9F780000
img = open("wp3_boot/kernel_raw.bin", "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

def at(va, n): return img[va - KTEXT: va - KTEXT + n]
def cstr(va, maxlen=80):
    out = bytearray(); off = va - KTEXT
    while len(out) < maxlen and 0 <= off < len(img):
        c = img[off + len(out)]
        if c == 0: break
        out.append(c)
    try: s = out.decode("ascii")
    except UnicodeDecodeError: return None
    return s if s and all(32 <= ord(ch) < 127 for ch in s) else None
def resolve_entry(f, hops=5):
    seen = set()
    while hops > 0 and f not in seen:
        seen.add(f); b = at(f, 5)
        if b[0:1] == b"\xe9":
            t = f + 5 + struct.unpack("<i", b[1:5])[0]
            if KTEXT <= t < TEXT_HI: f = t; hops -= 1; continue
        break
    return f
def padding_run(va, n=8):
    b = at(va, n)
    return len(b) == n and all(c in (0xCC, 0x90) for c in b)
def disasm_fn(start, cap=0x1000):
    out = []
    for i in md.disasm(at(start, cap), start):
        out.append(i)
        if padding_run(i.address + i.size, 8): break
    return out
def branch_target(i):
    if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
        try: return int(i.op_str, 16)
        except ValueError: return None
    return None

FN = 0x9EDF4130
ins = disasm_fn(FN, 0x400)
print(f"=== handler #1296 fn {FN:#x} ({len(ins)} insns) ===")
callees = {}
for i in ins:
    note = ""
    m2 = re.search(r"rip\s*([+-])\s*(0x[0-9a-f]+)", i.op_str)
    if m2:
        rt = i.address + i.size + int(m2.group(2), 16) * (-1 if m2.group(1) == "-" else 1)
        s = cstr(rt)
        note = f"  ; rip->{rt:#x}" + (f" {s!r}" if s else "")
    bt = branch_target(i)
    if bt is not None:
        r = resolve_entry(bt)
        note += f"  ; {i.mnemonic}->{r:#x}"
        if i.mnemonic == "call":
            callees.setdefault(r, []).append(i.address)
    print(f"  {i.address:#x}: {i.bytes.hex():<22} {i.mnemonic} {i.op_str}{note}")

print(f"\n=== callee quick-look ({len(callees)}) ===")
for r, sites in sorted(callees.items()):
    try: ci = disasm_fn(r, 0x600)
    except Exception: continue
    strs, loops, calls = [], 0, set()
    for i in ci:
        m2 = re.search(r"rip\s*([+-])\s*(0x[0-9a-f]+)", i.op_str)
        if m2:
            rt = i.address + i.size + int(m2.group(2), 16) * (-1 if m2.group(1) == "-" else 1)
            s = cstr(rt)
            if s: strs.append(s)
        if i.mnemonic.startswith("j") and i.op_str.startswith("0x"):
            t = int(i.op_str, 16)
            if t < i.address: loops += 1
        bt2 = branch_target(i)
        if bt2 is not None and i.mnemonic == "call": calls.add(resolve_entry(bt2))
    print(f"  {r:#x} (called from {[hex(s) for s in sites]}): {len(ci)}i loops={loops} "
          f"ncalls={len(calls)} strs={sorted(set(strs))[:4]}")
