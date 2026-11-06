#!/usr/bin/env python3
"""WP29 — locate the REAL caller of thunk 0x9e658db8 (->0x9e823290).
Clues: r14=thunk ptr in the live frame (indirect dispatch), saved rbx
(0x9e823290's rdi = out-slot) = 0xffff8e773f71eda0 (an ARENA pointer —
the caller allocates its slot array from the bump arena!).
A. SYSINIT table entries whose handler is the thunk
B. data refs (u32) to the thunk address (tables of fn ptrs)
C. walker loop disasm (0x9e926250..0x9e9263b0) — retry logic?
"""
import re, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

K = 0x9E3F0000
TEXT_HI = 0x9F780000
SET_LO, SET_HI = 0x9FE51FB0, 0x9FE55488
img = open("wp3_boot/kernel_raw.bin", "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

def at(va, n): return img[va - K: va - K + n]
def u64(va): return struct.unpack("<Q", at(va, 8))[0] & 0xFFFFFFFF
def u32(va): return struct.unpack("<I", at(va, 4))[0]
def cstr(va, maxlen=48):
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
def dis(start, cap, label):
    print(f"\n=== {label} ===")
    for i in md.disasm(at(start, cap), start):
        note = ""
        m = re.search(r"rip\s*([+-])\s*(0x[0-9a-f]+)", i.op_str)
        if m:
            rt = i.address + i.size + int(m.group(2), 16) * (-1 if m.group(1) == "-" else 1)
            s = cstr(rt)
            note = f"  ; rip->{rt:#x}" + (f" {s!r}" if s else "")
        print(f"  {i.address:#x}: {i.bytes.hex():<24} {i.mnemonic} {i.op_str}{note}")
        if padding_run(i.address + i.size, 8): break

THUNKS = [0x9E658DB8, 0x9E658ED8]

print("=== A. SYSINIT entries with handler == thunk ===")
for k in range(0, 1340):
    p = u64(SET_LO + 8 * k)
    if not (0x9FE73EC0 <= p < 0xA0FF9670) or p == 0 or u32(p) < 2: continue
    f = u64(p + 8)
    if f in THUNKS:
        print(f"  stage #{k}: entry {p:#x} handler {f:#x} (thunk!) arg={u64(p+16):#x}")

print("\n=== B. data refs (u32 LE) to thunk addresses ===")
refs = {}
for th in THUNKS:
    pat = struct.pack("<I", th)
    for m in re.finditer(re.escape(pat), img):
        va = K + m.start()
        refs.setdefault(va, th)
        print(f"  ref to {th:#x} at va {va:#x}  ctx: {img[m.start()-8:m.start()+12].hex(' ')}")

# cluster refs into tables
print("\n=== B2. ref neighborhoods (table shape) ===")
vas = sorted(refs)
for va in vas:
    print(f"  {va:#x} -> thunk {refs[va]:#x}; +0x40 window:")
    row = []
    for off in range(-0x20, 0x28, 8):
        q = u64(va + off) if 0 <= (va + off - K) < len(img) else 0
        row.append(f"{va+off:#x}: {q:#x}")
    print("    " + "\n    ".join(row))

print("\n=== C. walker loop (around the handler dispatch) ===")
dis(0x9E926250, 0x160, "mi_startup walk 0x9e926250..0x9e9263b0")
