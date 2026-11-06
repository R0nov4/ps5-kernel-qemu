#!/usr/bin/env python3
"""WP4 forensic: full int.log event analysis + static ELF analysis of the
0x3191250 recursive-#PF crash site.

Outputs a compact report to stdout + scripts/wp4_forensic_report.txt
"""
import re, struct, sys
from collections import Counter, deque

INTLOG = "./wp3_boot/int.log"
ELF    = "./download/ps5_kernel_1360_reconstructed.elf"
OUT    = "./scripts/wp4_forensic_report.txt"

T_VA, T_OFF, T_SZ = 0x9E3F0000, 0x1000, 0xCC0000
D_VA, D_OFF, D_SZ = 0x9F0B0000, 0xCC1000, 0x3174000

blob = open(ELF, "rb").read()
def va2img(va):
    lo = va & 0xFFFFFFFF
    if 0x9E3F0000 <= lo < 0x9F0B0000: return lo - 0x9E3F0000
    if 0x9F0B0000 <= lo < 0xA2224000: return 0xCC0000 + (lo - 0x9F0B0000)
    raise ValueError(hex(va))
def img_bytes(va, n):
    o = va2img(va)
    if o < 0xCC0000: return blob[T_OFF+o:T_OFF+o+n]
    return blob[D_OFF+(o-0xCC0000):D_OFF+(o-0xCC0000)+n]
def cstr(va, maxlen=120):
    try: b = img_bytes(va, maxlen)
    except Exception: return None
    b = b.split(b"\0",1)[0]
    return b if b and all(32 <= c < 127 for c in b) else None

# ---------------- capstone ----------------
import capstone
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = False
def disasm(va, n, note=""):
    code = img_bytes(va, n)
    lines = []
    for ins in md.disasm(code, va):
        lines.append(f"  {ins.address:#x}: {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}")
    return lines

report = []
def P(s=""):
    report.append(s); print(s)

# ============================================================
# PART A: int.log event stream analysis
# ============================================================
P("=" * 78)
P("PART A: int.log event stream (185MB, ~2.9M lines)")
P("=" * 78)

ev_re  = re.compile(r"^\s*(\d+): v=([0-9a-fA-F]{2}) e=([0-9a-fA-F]+) i=(\d+) cpl=(\d+) "
                    r"IP=([0-9a-fA-F]+):([0-9a-fA-F]+) pc=([0-9a-fA-F]+) SP=([0-9a-fA-F]+):([0-9a-fA-F]+) "
                    r"CR2=([0-9a-fA-F]+)")
kv_re  = re.compile(r"([A-Z0-9]+)=([0-9a-fA-F]+)")

events = []                 # (num, v, rip, rsp, cr2)
regs_of = {}                # event num -> dict of registers (for interesting ones)
KERN_LO, KERN_HI = 0xFFFFFFFF9E3F0000, 0xFFFFFFFFA2224000
BAD = 0x3191250

cur_regs, cur_num = {}, None
hist = Counter()
bad_rips = Counter()
bad_first3 = []
last_events = deque(maxlen=16)   # (event tuple, regs dict)
first_kern_seen = []
gp_events = []              # (num, rip, cr2)
other_cr2_late = []         # kernel-phase faults with CR2 != BAD

with open(INTLOG, "r", errors="replace") as f:
    for line in f:
        m = ev_re.match(line)
        if m:
            num, v, rip, rsp, cr2 = int(m.group(1)), m.group(2), int(m.group(7),16), int(m.group(9),16), int(m.group(10),16)
            if cur_num is not None and (cur_regs or True):
                ev = events_prev
                # finalize previous event
                if ev:
                    last_events.append((ev, dict(cur_regs)))
                    if ev[2] == BAD and len(bad_first3) < 3:
                        bad_first3.append((ev, dict(cur_regs)))
                    if ev[1] == "0d" and len(gp_events) < 40:
                        gp_events.append((ev[0], ev[2], ev[4]))
            events_prev = (num, v, rip, rsp, cr2)
            events.append(events_prev)
            hist[v] += 1
            cur_num, cur_regs = num, {}
            if rip == BAD or (KERN_LO <= rip < KERN_HI and v == "0e"):
                if rip != BAD and cr2 == BAD: bad_rips[hex(rip)] += 1
            if KERN_LO <= rip < KERN_HI:
                if cr2 == BAD: bad_rips[hex(rip)] += 1
                if len(first_kern_seen) < 6:
                    first_kern_seen.append((events_prev))
                if v == "0e" and cr2 != BAD and len(other_cr2_late) < 12:
                    other_cr2_late.append((events_prev))
            continue
        if cur_num is not None and "=" in line and line[:1].strip() == "":
            for k, val in kv_re.findall(line):
                if k in ("RAX","RBX","RCX","RDX","RSI","RDI","RBP","RSP","R8","R9","R10","R11",
                         "R12","R13","R14","R15","EFL","CR0","CR3","CR4","CCS","CCD","CCO","GDT","IDT","CS","SS","TR","LDT"):
                    cur_regs[k] = val
# finalize last event
if events_prev:
    last_events.append((events_prev, dict(cur_regs)))
    if events_prev[2] == BAD and len(bad_first3) < 3:
        bad_first3.append((events_prev, dict(cur_regs)))

P(f"\ntotal events: {len(events)}   vector histogram: {dict(hist)}")
nbad = sum(1 for e in events if e[4] == BAD)
P(f"events with CR2=0x{BAD:x}: {nbad}")
P(f"unique RIPs among kernel CR2==BAD faults: {dict(bad_rips.most_common(8))}")

# locate first BAD event index
idx_first = next((i for i,e in enumerate(events) if e[4] == BAD), None)
if idx_first is not None:
    P(f"\nfirst BAD event: #{events[idx_first][0]} (index {idx_first})")
    P("context (events before it):")
    for e in events[max(0,idx_first-10):idx_first+1]:
        P(f"   #{e[0]:>7} v={e[1]} rip={e[2]:#x} rsp={e[3]:#x} cr2={e[4]:#x}")

# RSP trajectory
if idx_first is not None:
    bads = [e for e in events if e[4] == BAD]
    P(f"\nRSP trajectory over BAD events: first={bads[0][3]:#x} last={bads[-1][3]:#x}")
    if len(bads) > 2:
        P(f"   per-event delta = {(bads[0][3]-bads[1][3]):#x}; total consumed = {(bads[0][3]-bads[-1][3]):#x}")
    # how many consecutive-from-first?
    P(f"   last BAD event number: {bads[-1][0]}")

P(f"\nfirst kernel-RIP events:")
for e in first_kern_seen:
    P(f"   #{e[0]:>7} v={e[1]} rip={e[2]:#x} rsp={e[3]:#x} cr2={e[4]:#x}")

P(f"\n#GP (v=0d) events in kernel phase (first 40): {len(gp_events)}")
for num, rip, cr2 in gp_events[:20]:
    P(f"   #{num:>7} rip={rip:#x} cr2={cr2:#x}")

P(f"\nkernel-phase #PF with CR2 != BAD (first 12): {len(other_cr2_late)}")
for e in other_cr2_late:
    P(f"   #{e[0]:>7} v={e[1]} rip={e[2]:#x} rsp={e[3]:#x} cr2={e[4]:#x}")

P("\nLAST 16 events (final cascade) with registers:")
for e, regs in list(last_events):
    P(f"   #{e[0]:>7} v={e[1]} rip={e[2]:#x} rsp={e[3]:#x} cr2={e[4]:#x}")
    if regs:
        keys = ["RAX","RBX","RCX","RDX","RSI","RDI","RBP","RSP","R8","R9","R14","CR3","IDT","CCS","CCD","CCO"]
        P("        " + "  ".join(f"{k}={regs[k]}" for k in keys if k in regs))

# first BAD event registers + string chasing
if bad_first3:
    e, regs = bad_first3[0]
    P(f"\n--- FIRST BAD event #{e[0]} full registers ---")
    for k, v in regs.items():
        P(f"   {k}={v}")
    for name in ("RDI","RSI","RCX","RBX","R8","R9","R12","R13","R14","R15"):
        if name in regs:
            try:
                va = int(regs[name], 16)
                if KERN_LO <= va < KERN_HI:
                    s = cstr(va)
                    if s: P(f"   {name}={va:#x} -> STRING: {s[:100]!r}")
                    else:
                        b = img_bytes(va, 16)
                        P(f"   {name}={va:#x} -> data: {b.hex()}")
            except Exception:
                pass

# ============================================================
# PART B: static analysis
# ============================================================
P("\n" + "=" * 78)
P("PART B: static ELF analysis")
P("=" * 78)

P("\n--- disasm of fault zone 0x9e7df1c0..0x9e7df290 ---")
for l in disasm(0x9E7DF1C0, 0xD0): P(l)

P("\n--- disasm of 0x9e7df2f0..0x9e7df4d0 (CCS region / stubs?) ---")
for l in disasm(0x9E7DF2F0, 0x1E0): P(l)

P("\n--- disasm of spin-timeout panic site 0x9e8b7970..0x9e8b79d8 ---")
for l in disasm(0x9E8B7970, 0x68): P(l)

# scan .data for the bad pointer value
P("\n--- .data scan for u64 0x0000000003191250 and 0xffff8e7703191250 ---")
text_img = blob[T_OFF:T_OFF+T_SZ]
data_img = blob[D_OFF:D_OFF+D_SZ]
for val, label in [(0x3191250, "truncated"), (0xFFFF8E7703191250, "full DMAP")]:
    needle = struct.pack("<Q", val)
    hits = []
    off = data_img.find(needle)
    while off != -1 and len(hits) < 12:
        hits.append(off)
        off = data_img.find(needle, off+1)
    P(f"  {label} {val:#x}: {len(hits)} hits in .data -> VAs: " +
      ", ".join(hex(D_VA+h) for h in hits))
    # also in .text (immediates)
    off = text_img.find(needle)
    thits = []
    while off != -1 and len(thits) < 6:
        thits.append(off); off = text_img.find(needle, off+1)
    if thits: P(f"    also {len(thits)} in .text -> VAs: " + ", ".join(hex(T_VA+h) for h in thits))

# RBX struct
P("\n--- RBX=0xffffffffa1971060 (.data) struct dump (mtx layout: name@+0 flags@+8 recurs@0xC lock@0x18) ---")
b = img_bytes(0xA1971060, 0x20)
for i in range(0, 0x20, 8):
    q = struct.unpack("<Q", b[i:i+8])[0]
    P(f"  +{i:#04x}: {q:#018x}" + (f"  (ptr->{hex(q)})" if KERN_LO <= q < KERN_HI else ""))
namep = struct.unpack("<Q", b[0:8])[0]
if KERN_LO <= namep < KERN_HI:
    s = cstr(namep)
    P(f"  name ptr {namep:#x} -> {s!r}")

open(OUT, "w").write("\n".join(report) + "\n")
print(f"\n[report saved to {OUT}]", file=sys.stderr)
