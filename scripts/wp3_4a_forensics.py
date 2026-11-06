#!/usr/bin/env python3
"""WP3-STEP 4a: Forensics on the 0x3191250 crash.
Parses ALL kernel-range events from int.log (finds the ORIGINAL fault before
the #GP cascade), decodes live IDT gates + TSS IST, disassembles the crash
context regions, and reads register-held pointers."""
import re, struct, sys
from capstone import *

IMG = "./wp3_boot/kernel_raw.bin"
INTLOG = "./wp3_boot/int.log"
KTEXT_VA = 0xFFFFFFFF9E3F0000

img = open(IMG, "rb").read()
def va2img(va):
    lo = va & 0xFFFFFFFF
    if 0x9E3F0000 <= lo < 0x9F0B0000:
        return lo - 0x9E3F0000
    if 0x9F0B0000 <= lo < 0xA2224000:
        return 0xCC0000 + (lo - 0x9F0B0000)
    return None
def rd(va, n):
    o = va2img(va)
    return None if o is None else img[o:o+n]
def cstr(va, maxlen=120):
    b = rd(va, maxlen)
    if b is None: return None
    z = b.find(b"\x00")
    s = b[:z if z >= 0 else maxlen]
    return s if all(32 <= c < 127 for c in s) else None

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False
def dis(va, n, mark=None):
    out = []
    for i in md.disasm(rd(va, n), va):
        m = "   <<<< " if mark and i.address == mark else ""
        out.append(f"  {i.address:#x}: {i.bytes.hex():20s} {i.mnemonic:9s} {i.op_str}{m}")
    return "\n".join(out)

# ============ 1. parse int.log events ============
print("=" * 70)
print("PART 1: ALL kernel-range events in int.log (CS=0020, IP 0xffffffff9e..)")
print("=" * 70)
events = []   # (num, vector, ip, sp, extra, regblock_lines)
cur = None
hdr = re.compile(r"^(\d+): v=(\w+) e=(\w+) i=(\d+) cpl=(\d+) IP=(\w+):(\w+) pc=(\w+) SP=(\w+):(\w+)(.*)$")
with open(INTLOG, "r", errors="replace") as f:
    for line in f:
        line = line.rstrip("\n")
        m = hdr.match(line)
        if m:
            num, vec = int(m.group(1)), int(m.group(2), 16)
            ip, sp = int(m.group(7), 16), int(m.group(9), 16)
            extra = m.group(10)
            cur = dict(num=num, vec=vec, ip=ip, sp=sp, extra=extra, regs=[])
            events.append(cur)
        elif cur is not None and cur["regs"] is not None:
            if line.startswith(("RAX=", "EAX=")):
                cur["regs"].append(line)
            elif re.match(r"^(R[0-9]+|RBX|RCX|RDX|RSI|RDI|RBP|RSP|RIP|EFER)", line):
                cur["regs"].append(line)
            elif line.startswith(("check_exception", "Triple fault")):
                cur["regs"].append(line)
                if "Triple" in line or "check" in line:
                    cur["regs"] = cur["regs"]  # keep
            elif line.strip() == "" or line.startswith(("CCS=", "DR", "FCW")):
                pass
            else:
                # end of this regblock heuristically: next event header resets cur
                pass

kern = [e for e in events if 0xFFFFFFFF9E000000 <= e["ip"] < 0xFFFFFFFFA4000000]
print(f"total events: {len(events)}, kernel-range events: {len(kern)}")
for e in kern:
    print(f"\n--- event #{e['num']} v={e['vec']:#x} IP={e['ip']:#x} SP={e['sp']:#x}{e['extra']}")
    for r in e["regs"][:22]:
        print("   ", r)

# also show the raw 30 lines around the FIRST kernel event for context
if kern:
    first = kern[0]["num"]

# ============ 2. IDT gates + TSS ============
print()
print("=" * 70)
print("PART 2: live IDT gates (rebuilt by machine_init, from image @0xa1fa4300)")
print("=" * 70)
IDT_VA = 0xA1FA4300
def gate(vec):
    b = rd(IDT_VA + vec * 16, 16)
    if b is None: return None
    off_lo, sel, attr, off_mid, off_hi = struct.unpack("<HHHIH", b[:12])
    # FreeBSD/Sony order: off_lo, sel, attr(off_mid packs attrs), ...
    # standard x86 gate: off_lo(2) sel(2) ist/attr(2) off_mid(2) off_hi(4)
    off = off_lo | (off_mid << 16) | (off_hi << 32)
    return dict(sel=sel, attr=attr, off=off)
interesting = sorted(set([3, 6, 8, 0xE, 0xD, 2, 0, 1, 4, 5, 7, 9, 0x10, 0x92] + [e["vec"] for e in kern]))
for v in interesting:
    g = gate(v)
    if g:
        print(f"  gate[{v:#04x}]: sel={g['sel']:#x} attr={g['attr']:#06x} target={g['off']:#x}")
# thunk resolution: read 5 bytes at each distinct target
targets = {}
for v in interesting:
    g = gate(v)
    if g:
        t = g["off"]
        if t not in targets:
            b = rd(t, 5)
            if b and b[0] == 0xE9:
                rel = struct.unpack("<i", b[1:5])[0]
                targets[t] = t + 5 + rel
print("\n  thunk -> stub resolution:")
for t, s in sorted(targets.items()):
    print(f"    thunk {t:#x} -> stub {s:#x}")

print()
print("PART 2b: TSS @0xa1fa6fe0 (IST stacks)")
b = rd(0xA1FA6FE0, 0x70)
if b:
    for i, name in [(0x04, "rsp0"), (0x0C, "rsp1"), (0x14, "rsp2")]:
        print(f"  {name} = {struct.unpack('<Q', b[i:i+8])[0]:#x}")
    for i in range(7):
        ist = struct.unpack("<Q", b[0x1C + i * 8:0x24 + i * 8])[0]
        if ist: print(f"  ist[{i+1}] = {ist:#x}")

# ============ 3. crash-context disasm ============
print()
print("=" * 70)
print("PART 3: crash-context regions")
print("=" * 70)
print("\n--- 0x9eef7a00 region (RCX=0x9eef7a01, R10=0x9eef7a20, RSI=0x9eef7a70):")
print(dis(0x9EEF79C0, 0x140))
print("\n--- 0x9e7df460 region (RBP=0x9e7df4a0, R14=0x9e7df4b0):")
print(dis(0x9E7DF460, 0xC0))
print("\n--- thunk island 0x9e65a300..0x9e65a380 (event IPs):")
print(dis(0x9E65A300, 0x80))

# ============ 4. register pointers ============
print()
print("=" * 70)
print("PART 4: register-held pointers")
print("=" * 70)
for name, va in [("R9", 0x9F65DAE4), ("RBX", 0xA1971060)]:
    s = cstr(va)
    b = rd(va, 24)
    print(f"  {name} = {va:#x}: bytes={b.hex() if b else None}")
    if s: print(f"        STRING: {s!r}")

# search for the 'Testing system memory' string VA
idx = img.find(b"Testing system memory")
while idx != -1 and idx < len(img):
    if idx < 0xCC0000:
        va = 0x9E3F0000 + idx
    else:
        va = 0x9F0B0000 + (idx - 0xCC0000)
    print(f"  'Testing system memory' found at VA {va:#x}")
    idx = img.find(b"Testing system memory", idx + 1)

# what is at KVA(0x3191250) = phys 0x3191250: nothing in image (below 0x1E3F0000).
print(f"\n  CR2/RAX = 0x3191250 = DMAP(0x3191250)&0xffffffff (0xffff8e7703191250 truncated)")
