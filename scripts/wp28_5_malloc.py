#!/usr/bin/env python3
"""WP28 — disasm malloc 0x9eff8b50 (M_WAITOK retry loop?) + stage#1296 callees."""
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

def show(fn, cap=0x400, label=""):
    print(f"\n=== {fn:#x} {label} ===")
    ins = disasm_fn(fn, cap)
    for i in ins:
        note = ""
        m2 = re.search(r"rip\s*([+-])\s*(0x[0-9a-f]+)", i.op_str)
        if m2:
            rt = i.address + i.size + int(m2.group(2), 16) * (-1 if m2.group(1) == "-" else 1)
            s = cstr(rt)
            note = f"  ; rip->{rt:#x}" + (f" {s!r}" if s else "")
        bt = branch_target(i)
        if bt is not None:
            note += f"  ; {i.mnemonic}->{resolve_entry(bt):#x}"
        print(f"  {i.address:#x}: {i.bytes.hex():<24} {i.mnemonic} {i.op_str}{note}")
    return ins

show(0x9EFF8B50, 0x200, "malloc (stage#1296 call @0x9edf41d9, flags=0x102 M_WAITOK|M_ZERO)")
show(0x9EDF8650, 0x40, "canvas-get-A(edi)")
show(0x9EDF8670, 0x40, "canvas-get-B(edi)")
show(0x9E7B33F0, 0x100, "post-malloc ctor caller")
show(0x9EE30CA8, 0x80, "mtx_init-ish 'canvasmap'")
