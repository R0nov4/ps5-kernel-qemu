#!/usr/bin/env python3
"""WP3-4a v2: full event parse (leading-space fix) + faulting-instruction disasm."""
import re, struct
from capstone import *

IMG = "./wp3_boot/kernel_raw.bin"
INTLOG = "./wp3_boot/int.log"

img = open(IMG, "rb").read()
def va2img(va):
    lo = va & 0xFFFFFFFF
    if 0x9E3F0000 <= lo < 0x9F0B0000: return lo - 0x9E3F0000
    if 0x9F0B0000 <= lo < 0xA2224000: return 0xCC0000 + (lo - 0x9F0B0000)
    return None
def rd(va, n):
    o = va2img(va); return None if o is None else img[o:o+n]
def cstr(va, maxlen=100):
    b = rd(va, maxlen)
    if b is None: return None
    z = b.find(b"\x00"); s = b[:z if z >= 0 else maxlen]
    return s if all(32 <= c < 127 for c in s) else None

md = Cs(CS_ARCH_X86, CS_MODE_64)
def dis(va, back, fwd, mark=None):
    out = []
    for i in md.disasm(rd(va - back, back + fwd), va - back):
        m = "   <<<< FAULT" if mark and i.address == mark else ""
        out.append(f"  {i.address:#x}: {i.bytes.hex():22s} {i.mnemonic:9s} {i.op_str}{m}")
    return "\n".join(out)

hdr = re.compile(r"^\s*(\d+): v=(\w+) e=(\w+) i=(\d+) cpl=(\d+) IP=(\w+):(\w+) pc=(\w+) SP=(\w+):(\w+)(.*)$")
events = []
with open(INTLOG, "r", errors="replace") as f:
    for line in f:
        m = hdr.match(line.rstrip("\n"))
        if m:
            events.append(dict(num=int(m.group(1)), vec=int(m.group(2), 16),
                               ip=int(m.group(7), 16), sp=int(m.group(9), 16),
                               extra=m.group(10), regs={}, raw=[]))
        elif events and line.startswith(("RAX=", "EAX=")):
            events[-1]["regs"]["RAX"] = line.split("=")[1].split()[0]
            for r in line.split()[1:]:
                if "=" in r:
                    k, v = r.split("="); events[-1]["regs"][k] = v
        elif events and re.match(r"^\s*(R[0-9]+\s*=|RBX|RCX|RDX|RSI|RDI|RBP|RSP|RIP|CR[0-9]|EFER)", line):
            for r in line.split():
                if "=" in r:
                    k, v = r.split("="); events[-1]["regs"][k] = v
                    if k == "CR2": events[-1]["cr2"] = v

print(f"TOTAL events parsed: {len(events)}")
print(f"\n{'#':>7} {'vec':>5} {'IP':>18} {'CR2':>18} {'RAX':>18} {'RSP':>18}")
for e in events[:40]:
    print(f"{e['num']:>7} {e['vec']:#05x} {e['ip']:#18x} {e.get('cr2','-'):>18} {e['regs'].get('RAX','-'):>18} {e['sp']:#18x}")
print("...")
# find where the degenerate repeating pattern starts
pat_start = None
for i in range(len(events) - 1):
    if events[i]["ip"] == events[i+1]["ip"] and events[i]["vec"] == events[i+1]["vec"]:
        # look ahead 20 for same
        if i + 20 < len(events) and all(events[i+k]["ip"] == events[i]["ip"] and events[i+k]["vec"] == events[i]["vec"] for k in (0, 2, 4)):
            pat_start = i; break
print(f"\ndegenerate pattern starts around event index {pat_start} (event #{events[pat_start]['num']})" if pat_start else "\nno degenerate pattern found")

print("\n" + "=" * 70)
print("FULL register dumps of the first 8 events:")
print("=" * 70)
for e in events[:8]:
    print(f"\n--- event #{e['num']} v={e['vec']:#x} IP={e['ip']:#x} SP={e['sp']:#x} {e['extra'].strip()}")
    for k in ["RAX","RBX","RCX","RDX","RSI","RDI","RBP","RSP","R8","R9","R10","R11","R12","R13","R14","R15","CR2","CR3"]:
        if k in e["regs"]: print(f"    {k:>4} = {e['regs'][k]}")

print("\n" + "=" * 70)
print("FAULTING INSTRUCTION DISASM:")
print("=" * 70)
for e in events[:6]:
    print(f"\n--- event #{e['num']} v={e['vec']:#x} at {e['ip']:#x}:")
    print(dis(e["ip"], 0x50, 0x30, mark=e["ip"]))

print("\n" + "=" * 70)
print("STRING lookups:")
print("=" * 70)
for name, va in [("ev1 R13", 0x9F6CDA95), ("ev1 RSI", 0xA1DC1CC0), ("ev0 RBX", 0x9F67B8EA)]:
    s = cstr(va)
    print(f"  {name} {va:#x}: {s!r}" if s else f"  {name} {va:#x}: (not a printable string)")

# what's at DMAP(0x1974000)? = phys 0x1974000 (stale module copy area) — show bytes
print(f"\n  phys 0x1974000 (DMAP target of ev1 RBX): low image bytes at module area (garbage):")
# the module copy region is phys [0x110000..0x3F54000) approx — we can't read phys below 0x1E3F0000 from img
print("    (outside kernel image — stale QEMU initrd copy, garbage by definition)")

# R14/R15=0xa1130a20 & RBP=0xa11309e0 boot stack — peek stack contents? not possible from img.
