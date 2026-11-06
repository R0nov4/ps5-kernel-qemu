#!/usr/bin/env python3
"""WP4 forensic v2: fixed regex + phase timeline + key-site disassembly."""
import re, struct, sys
from collections import Counter, deque
import capstone

INTLOG = "./wp3_boot/int.log"
ELF    = "./download/ps5_kernel_1360_reconstructed.elf"
OUT    = "./scripts/wp4_forensic2_report.txt"

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
def cstr(va, maxlen=160):
    try: b = img_bytes(va, maxlen)
    except Exception: return None
    b = b.split(b"\0",1)[0]
    return b if b and all(32 <= c < 127 for c in b) else None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail = True
def disasm(va, n, resolve_str=True):
    out = []
    code = img_bytes(va, n)
    for ins in md.disasm(code, va):
        ann = ""
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                tgt = ins.address + ins.size + op.mem.disp
                ann = f"   ; -> 0x{tgt:x}"
                if resolve_str:
                    s = cstr(tgt)
                    if s and len(s) > 3: ann += f"  {s[:80]!r}"
        out.append(f"  {ins.address:#x}: {ins.bytes.hex():<22} {ins.mnemonic} {ins.op_str}{ann}")
    return out

report = []
def P(s=""): report.append(s); print(s)

# ---- parse ----
ev_re = re.compile(r"^\s*(\d+): v=([0-9a-fA-F]{2}) e=([0-9a-fA-F]+) i=(\d+) cpl=(\d+) "
                   r"IP=([0-9a-fA-F]+):([0-9a-fA-F]+) pc=([0-9a-fA-F]+) SP=([0-9a-fA-F]+):([0-9a-fA-F]+) "
                   r"(?:CR2=([0-9a-fA-F]+)|env->regs\[(\w+)\]=([0-9a-fA-F]+))")
kv_re = re.compile(r"([A-Z0-9]+)=([0-9a-fA-F]+)")
STUB_LO, STUB_HI = 0x9E642C00, 0x9E648200

events = []          # (num, v, rip, rsp, cr2_or_None, gp_reg, gp_val)
cur_regs, cur_ev = {}, None
hist = Counter(); cr2_hist = Counter()
gp_rips = Counter(); gp_eax = Counter()
first_of_cr2 = {}    # cr2 -> (event tuple, regs)
last16 = deque(maxlen=14)
n = 0
with open(INTLOG, "r", errors="replace") as f:
    for line in f:
        m = ev_re.match(line)
        if m:
            if cur_ev is not None:
                last16.append((cur_ev, dict(cur_regs)))
                if cur_ev[4] is not None and cur_ev[4] not in first_of_cr2:
                    first_of_cr2[cur_ev[4]] = (cur_ev, dict(cur_regs))
            cur_ev = (int(m.group(1)), m.group(2), int(m.group(8),16), int(m.group(10),16),
                      int(m.group(11),16) if m.group(11) else None,
                      m.group(12), int(m.group(13),16) if m.group(13) else None)
            events.append(cur_ev); n += 1
            hist[cur_ev[1]] += 1
            if cur_ev[4] is not None: cr2_hist[cur_ev[4]] += 1
            if cur_ev[1] == "0d":
                gp_rips[hex(cur_ev[2])] += 1
                if cur_ev[6] is not None: gp_eax[cur_ev[6]] += 1
            cur_regs = {}
            continue
        if cur_ev is not None and "=" in line and not line.strip().startswith(("RIP=","ES ","CS ","SS ","DS ","FS ","GS ","LDT","TR ","GDT","IDT","CR0","DR","CCS","EFER","check_","RAX","RSI","R12")):
            pass
        if cur_ev is not None and ("=" in line):
            for k, val in kv_re.findall(line):
                if k in ("RAX","RBX","RCX","RDX","RSI","RDI","RBP","RSP","R8","R9","R10","R11","R12","R13","R14","R15","RIP","CR3","CCS","CCD","CCO"):
                    cur_regs[k] = val
if cur_ev is not None:
    last16.append((cur_ev, dict(cur_regs)))
    if cur_ev[4] is not None and cur_ev[4] not in first_of_cr2:
        first_of_cr2[cur_ev[4]] = (cur_ev, dict(cur_regs))

P("="*78); P("PART A: event stream (fixed parser)"); P("="*78)
P(f"total parsed events: {n}   vectors: {dict(hist)}")
P(f"#GP RIPs: {dict(gp_rips.most_common(6))}")
P(f"#GP EAX values: {dict(gp_eax.most_common(6))}")
P(f"\nCR2 phase histogram (top 10):")
for c, cnt in cr2_hist.most_common(10):
    P(f"   CR2={c:#x}: {cnt} events   (first at #{first_of_cr2[c][0][0]})")

P("\n--- FIRST 4 events with full regs ---")
for ev, regs in list(last16)[:0]: pass
for i, ev in enumerate(events[:4]):
    P(f"#{ev[0]} v={ev[1]} rip={ev[2]:#x} rsp={ev[3]:#x} cr2={ev[4] if ev[4] is None else hex(ev[4])} gp={ev[5]}:{ev[6] if ev[6] is None else hex(ev[6])}")

P("\n--- FIRST event of each major CR2 phase (with registers) ---")
for c in [0x100, 0x20, 0xFFFFFFFF9F9844FF, 0x3191250]:
    if c in first_of_cr2:
        ev, regs = first_of_cr2[c]
        P(f"\nCR2={c:#x}  first event #{ev[0]}: rip={ev[2]:#x} rsp={ev[3]:#x} v={ev[1]}")
        keys = ["RAX","RBX","RCX","RDX","RSI","RDI","RBP","RSP","R8","R9","R10","R11","R12","R13","R14","R15","CR3","CCS","CCD","CCO"]
        P("   " + " ".join(f"{k}={regs[k]}" for k in keys if k in regs))
        for nm in ("RCX","RSI","RDI","R9","R10"):
            if nm in regs:
                try:
                    va = int(regs[nm],16)
                    s = cstr(va)
                    if s: P(f"   {nm}={va:#x} -> STRING {s[:100]!r}")
                except Exception: pass

P("\n--- LAST 14 events (final cascade) ---")
for ev, regs in list(last16):
    P(f"#{ev[0]} v={ev[1]} rip={ev[2]:#x} rsp={ev[3]:#x} cr2={ev[4] if ev[4] is None else hex(ev[4])} gp={ev[5]}:{ev[6] if ev[6] is None else hex(ev[6])}")

# stub-region #PF events: what CR2?
stub_pfs = [e for e in events if STUB_LO <= e[2] < STUB_HI and e[1]=="0e"]
P(f"\n#PF events with RIP inside extended-stub region [{STUB_LO:#x},{STUB_HI:#x}): {len(stub_pfs)}")
if stub_pfs:
    sc = Counter(hex(e[4]) for e in stub_pfs if e[4] is not None)
    P(f"   their CR2 values: {dict(sc.most_common(6))}")
    P(f"   their RIP range: {min(e[2] for e in stub_pfs):#x}..{max(e[2] for e in stub_pfs):#x}")
    P(f"   first: #{stub_pfs[0][0]} rip={stub_pfs[0][2]:#x} rsp={stub_pfs[0][3]:#x} cr2={stub_pfs[0][4] and hex(stub_pfs[0][4])}")

# ============================================================
P("\n"+"="*78); P("PART B: static disassembly of key sites"); P("="*78)

P("\n--- B1. event-#0 fault site 0x9ec227c8 ---")
for l in disasm(0x9EC22798, 0x60): P(l)
P("\n--- B2. event-#1 fault site 0x9ee30cc5 (trap path?) ---")
for l in disasm(0x9EE30C95, 0x60): P(l)
P("\n--- B3. #GP site 0x9ea1d440 ---")
for l in disasm(0x9EA1D410, 0x60): P(l)
P("\n--- B4. trap handler RIP 0x9eef793c region ---")
for l in disasm(0x9EEF7900, 0x80): P(l)
P("\n--- B5. gap 0x9e7df280..0x9e7df2f0 (panic fn prologue?) ---")
for l in disasm(0x9E7DF280, 0x70): P(l)
P("\n--- B6. stub containing 0x9e64482c ---")
for l in disasm(0x9E6447C0, 0xC0): P(l)

P("\n--- B7. globals ---")
for va, label in [(0xA1B5BFA8, "dispatcher global fn-ptr [rip+0x37b6d6a]"),
                  (0x9E65D180, "dispatch table base (lea rip-0x1820cd)")]:
    try:
        b = img_bytes(va, 0x50)
        P(f"{label} @ {va:#x}:")
        for i in range(0, 0x50, 8):
            q = struct.unpack("<Q", b[i:i+8])[0]
            P(f"   +{i:#04x}: {q:#018x}")
    except Exception as e:
        P(f"{label}: ERR {e}")

open(OUT, "w").write("\n".join(report) + "\n")
print(f"\n[report -> {OUT}]", file=sys.stderr)
