#!/usr/bin/env python3
"""WP29 — find who invokes the thunks 0x9e658db3 (->0x9e823290) and
0x9e658ed3 (->0x9e9e27f0), and what happens on their 0-return."""
import re, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

K = 0x9E3F0000
TEXT_HI = 0x9F780000
img = open("wp3_boot/kernel_raw.bin", "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

def at(va, n): return img[va - K: va - K + n]
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
def prologue_back(va, w=0x1000):
    lo = max(K, va - w)
    idx = bytes(img).rfind(b"\x55\x48\x89\xe5", lo - K, va - K + 1)
    return K + idx if idx >= 0 else None

def dis(start, cap, label):
    print(f"\n=== {label} ===")
    for i in md.disasm(at(start, cap), start):
        note = ""
        m = re.search(r"rip\s*([+-])\s*(0x[0-9a-f]+)", i.op_str)
        if m:
            rt = i.address + i.size + int(m.group(2), 16) * (-1 if m.group(1) == "-" else 1)
            s = cstr(rt)
            note = f"  ; rip->{rt:#x}" + (f" {s!r}" if s else "")
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
            try:
                t = int(i.op_str, 16)
                note += f"  ; {i.mnemonic}->{t:#x}"
            except Exception: pass
        print(f"  {i.address:#x}: {i.bytes.hex():<22} {i.mnemonic} {i.op_str}{note}")
        if padding_run(i.address + i.size, 8): break

THUNKS = {0x9E658DB3: 0x9E823290, 0x9E658ED3: 0x9E9E27F0}
print("=== thunk bytes ===")
for th, tgt in THUNKS.items():
    print(f"thunk {th:#x}: {at(th, 8).hex(' ')} (-> {tgt:#x})")

print("\n=== A. direct call/jmp sites targeting the thunks ===")
for th in THUNKS:
    for m in re.finditer(rb"[\xe8\xe9]", img[:TEXT_HI - K]):
        p = m.start()
        t = K + p + 5 + struct.unpack("<i", img[p+1:p+5])[0]
        if t == th:
            W = prologue_back(K + p)
            print(f"  call/jmp thunk {th:#x} from {K+p:#x} (fn {W and hex(W)})")

print("\n=== B. data references (u32/u64) to the thunks ===")
for th in THUNKS:
    pat4 = struct.pack("<I", th)
    for m in re.finditer(re.escape(pat4), img):
        p = m.start()
        va = K + p
        # skip if inside code (rough: preceding byte is e8/e9 handled above)
        print(f"  data ref to {th:#x} at va {va:#x}: ctx {img[p-8:p+12].hex(' ')}")

print("\n=== C. disasm around each data-ref site (find the loop!) ===")
# find the most likely referencing function: refs inside .data tables — look at
# the thunk neighborhood instead: what sits around 0x9e658db3 in the thunk zone
dis(0x9E658D80, 0x60, "thunk zone around 0x9e658db3")
dis(0x9E658EA0, 0x60, "thunk zone around 0x9e658ed3")
