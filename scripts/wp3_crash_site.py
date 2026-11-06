#!/usr/bin/env python3
"""WP3 crash-site identification: RIP=0xffffffff9e65a320 from int.log tail."""
import json, sys
sys.path.insert(0, './scripts')
from capstone import *

DUMP = './ps5/dump13/kernel-13.60-live.bin'
META = json.load(open('./ps5/dump13/kernel-13.60-live.bin.json'))

# Build VA->file offset map from segments
segs = META['segments'] if 'segments' in META else META
def va2off(va):
    for s in (segs if isinstance(segs, list) else segs.get('segments', [])):
        sv = s['va'] if isinstance(s, dict) and 'va' in s else None
        if sv is None:
            continue
        sz = s.get('zsize') or s.get('size') or 0
        if sv <= va < sv + sz:
            return s.get('offset', 0) + (va - sv)
    return None

# Fallback: known text mapping .text va 0xffffffff9e3f0000 -> off 0
def va2off2(va):
    if 0xffffffff9e3f0000 <= va < 0xffffffff9e3f0000 + 0xCC0000:
        return va - 0xffffffff9e3f0000
    if 0xffffffff9f0b0000 <= va < 0xffffffff9f0b0000 + 0x3174000:
        return va - 0xffffffff9f0b0000
    return None

blob = open(DUMP, 'rb').read()

def read(va, n):
    off = va2off2(va)
    if off is None:
        return None
    return blob[off:off+n]

def cstr(va, maxlen=96):
    off = va2off2(va)
    if off is None:
        # try data segment mapping via zsize table
        return None
    b = blob[off:off+maxlen]
    z = b.find(b'\0')
    return b[:z if z >= 0 else maxlen].decode('ascii', 'replace')

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False

print("=== CRASH SITE: disasm around RIP 0xffffffff9e65a320 ===")
code = read(0xffffffff9e65a2f0, 0x70)
for i in md.disasm(code, 0xffffffff9e65a2f0):
    mark = '  <-- RIP (faulting instr)' if i.address == 0xffffffff9e65a320 else ''
    print(f"  {i.address:#x}: {i.mnemonic:8s} {i.op_str}{mark}")

print()
print("=== registers of interest from int.log ===")
print("  RAX = 0x3191250  (== CR2: faulting DATA address)")
print("  R8  = 0xffffffff9e65c4b8 (putchar thunk)")
print("  RSI = 0xffffffff9eef7a70, RCX = 0xffffffff9eef7a01")
print()
print("=== string at 0xffffffff9eef7a70 ===")
s = cstr(0xffffffff9eef7a70)
print(f"  {s!r}")
s2 = cstr(0xffffffff9eef7a01)
print(f"  0x9eef7a01: {s2!r}")

print()
print("=== what is 0x3191250? (low VA ~49.5MB) ===")
print("  KVA  0xffffffff803191250 = phys 0x3191250 (inside kernel image .data range!')")
print("  image .data = [0x1F0B0000, 0x22224000) phys -> 0x3191250 is BELOW image (phys 51.9MB)")
print()

# Look for what the printf was printing - check machine_init printf calls
print("=== thunks near crash: what does 0x9e65a320 belong to? ===")
code2 = read(0xffffffff9e65a7a0, 0x20)
for i in md.disasm(code2, 0xffffffff9e65a7a0):
    print(f"  {i.address:#x}: {i.mnemonic:8s} {i.op_str}")
