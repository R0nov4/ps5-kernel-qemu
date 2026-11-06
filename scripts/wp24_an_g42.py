#!/usr/bin/env python3
"""WP24 G42 analysis — NULL-zone crash @0x9e82d71e (CR2=0x68, after BAPM C0 wc param).

Sections (output kept short on purpose):
  A) failure path 0x9e82d7c0 -> ret   (return value + epilogue of crash fn)
  B) unguarded early [rdi] loads in 0x9e82d000..0x9e82e200 (sibling sweep)
  C) xrefs -> 0x9e82d710              (callers / G43 verdict material)
  D) BAPM strings + lea xrefs to the "C0 wc param" site
  E) disasm around the BAPM print site (caller shape)
  F) pristine CC slot runs in 0x9e402000..0x9e406000 (stub real estate)
"""
import re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"
img = open(IMG, "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

def dis(va, n, stop_ret=False, maxn=40):
    out = []
    for i in md.disasm(img[va - KTEXT:va - KTEXT + n], va):
        out.append(i)
        if (stop_ret and i.mnemonic in ("ret", "jmp")) or len(out) >= maxn:
            break
    return out

def show(ins):
    for i in ins:
        print(f"  {i.address:#x}: {i.bytes.hex():<20} {i.mnemonic} {i.op_str}")

print("== A) failure path 0x9e82d7c0 -> ret ==")
show(dis(0x9e82d7c0, 0x90, stop_ret=True, maxn=20))

print("== B) unguarded early [rdi] loads (0x9e82d000..0x9e82e200) ==")
lo, hi = 0x9e82d000, 0x9e82e200
for m in re.finditer(rb"\x55\x48\x89\xe5", img[lo - KTEXT:hi - KTEXT]):
    va = lo + m.start()
    ins = dis(va, 0x40, maxn=14)
    hooked = False
    for i in ins:
        if i.mnemonic in ("jmp", "call") and i.op_str.startswith("0x9e4"):  # already stubbed
            hooked = True
            break
    if hooked:
        continue
    for i in ins:
        o = i.op_str.replace(" ", "")
        if i.mnemonic == "test" and o in ("rdi,rdi", "edi,edi"):
            break
        if "[rdi" in o and i.mnemonic != "lea":
            tag = "MAIN" if va == 0x9e82d710 else "SIBLING"
            print(f"  {va:#x} [{tag}]: {i.address:#x} {i.mnemonic} {i.op_str}")
            break

print("== C) xrefs -> 0x9e82d710 ==")
hits = []
for m in re.finditer(rb"[\xe8\xe9]", img[:-5]):
    p = m.start()
    rel = int.from_bytes(img[p + 1:p + 5], "little", signed=True)
    if KTEXT + p + 5 + rel == 0x9e82d710:
        hits.append(KTEXT + p)
print(f"  {len(hits)}: " + ", ".join(hex(h) for h in hits[:10]))

print("== D) BAPM strings ==")
for m in list(re.finditer(rb"BAPM", img))[:8]:
    print(f"  {KTEXT + m.start():#x}: {img[m.start() - 4:m.start() + 36]!r}")

s = img.find(b"C0 wc param")
if s >= 0:
    sva = KTEXT + s
    print(f"== E) lea xrefs -> {sva:#x} + caller shape ==")
    for m in re.finditer(rb"\x48\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", img[:-7]):
        p = m.start()
        rel = int.from_bytes(img[p + 3:p + 7], "little", signed=True)
        if KTEXT + p + 7 + rel == sva:
            print(f"  lea @ {KTEXT + p:#x}:")
            show(dis(KTEXT + p, 0x70, maxn=16))

print("== F) pristine CC slot runs 0x9e402000..0x9e406000 ==")
i, end = 0x9E402000 - KTEXT, 0x9E406000 - KTEXT
tot = 0
while i < end:
    if img[i] == 0xCC:
        j = i
        while j < end and img[j] == 0xCC:
            j += 1
        if j - i >= 0x60:
            print(f"  {KTEXT + i:#x} len={j - i:#x}")
            tot += j - i
        i = j
    else:
        i += 1
print(f"  total free CC >= 0x60: {tot:#x}")
