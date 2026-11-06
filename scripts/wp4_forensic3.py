#!/usr/bin/env python3
"""WP4 forensic v3: missing pieces — event0/1 regs, stub disasm, thunk bytes,
.data scans for trash pointers, panic-fn internals."""
import re, struct, sys
from collections import Counter
import capstone

INTLOG = "./wp3_boot/int.log"
ELF    = "./download/ps5_kernel_1360_reconstructed.elf"
OUT    = "./scripts/wp4_forensic3_report.txt"
T_VA, T_OFF, T_SZ = 0x9E3F0000, 0x1000, 0xCC0000
D_VA, D_OFF, D_SZ = 0x9F0B0000, 0xCC1000, 0x3174000
blob = open(ELF, "rb").read()
text_img = blob[T_OFF:T_OFF+T_SZ]; data_img = blob[D_OFF:D_OFF+D_SZ]
def va2img(va):
    lo = va & 0xFFFFFFFF
    if 0x9E3F0000 <= lo < 0x9F0B0000: return lo - 0x9E3F0000
    if 0x9F0B0000 <= lo < 0xA2224000: return 0xCC0000 + (lo - 0x9F0B0000)
    raise ValueError(hex(va))
def img_bytes(va, n):
    o = va2img(va)
    return (blob[T_OFF+o:T_OFF+o+n] if o < 0xCC0000 else blob[D_OFF+(o-0xCC0000):D_OFF+(o-0xCC0000)+n])
def cstr(va, maxlen=200):
    try: b = img_bytes(va, maxlen)
    except Exception: return None
    b = b.split(b"\0",1)[0]
    return b if b and all(32 <= c < 127 for c in b) else None
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail = True
def disasm(va, n, resolve=True, limit=60):
    out = []
    for ins in md.disasm(img_bytes(va, n), va):
        ann = ""
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                tgt = ins.address + ins.size + op.mem.disp
                ann = f"  ; ->0x{tgt:x}"
                s = cstr(tgt) if resolve else None
                if s and len(s) > 3: ann += f" {s[:60]!r}"
        out.append(f"  {ins.address:#x}: {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}{ann}")
    return out[:limit]
report = []
def P(s=""): report.append(s); print(s)

# --- re-parse just enough: first_of_cr2 regs for 0xc08 and 0x2718d834d1cc, stub-region stats
ev_re = re.compile(r"^\s*(\d+): v=([0-9a-fA-F]{2}) e=([0-9a-fA-F]+) i=(\d+) cpl=(\d+) "
                   r"IP=([0-9a-fA-F]+):([0-9a-fA-F]+) pc=([0-9a-fA-F]+) SP=([0-9a-fA-F]+):([0-9a-fA-F]+) "
                   r"(?:CR2=([0-9a-fA-F]+)|env->regs\[(\w+)\]=([0-9a-fA-F]+))")
kv_re = re.compile(r"([A-Z0-9]+)=([0-9a-fA-F]+)")
STUB_LO, STUB_HI = 0x9E642C00, 0x9E648200
want = {0xc08, 0x2718D834D1CC}
first_regs = {}
cur_ev, cur_regs = None, {}
stub_events = []          # (num, rip32, rsp, cr2)
stub_rip_hist = Counter(); stub_cr2_hist = Counter()
ud_rips = Counter()
with open(INTLOG, "r", errors="replace") as f:
    for line in f:
        m = ev_re.match(line)
        if m:
            if cur_ev is not None:
                c2 = cur_ev[4]
                if c2 is not None:
                    if c2 in want and c2 not in first_regs: first_regs[c2] = dict(cur_regs)
                    r32 = cur_ev[2] & 0xFFFFFFFF
                    if STUB_LO <= r32 < STUB_HI and cur_ev[1] == "0e":
                        stub_events.append(cur_ev)
                        stub_rip_hist[hex(r32)] += 1
                        if c2 is not None: stub_cr2_hist[hex(c2)] += 1
                if cur_ev[1] == "06":
                    ud_rips[hex(cur_ev[2] & 0xFFFFFFFF)] += 1
            cur_ev = (int(m.group(1)), m.group(2), int(m.group(8),16), int(m.group(10),16),
                      int(m.group(11),16) if m.group(11) else None)
            cur_regs = {}
            continue
        if cur_ev is not None and "=" in line:
            for k, val in kv_re.findall(line):
                if k in ("RAX","RBX","RCX","RDX","RSI","RDI","RBP","RSP","R8","R9","R10","R11","R12","R13","R14","R15","CR3","CCS","CCD","CCO"):
                    cur_regs[k] = val

P("="*78); P("v3: missing pieces"); P("="*78)
P(f"stub-region [#PF with RIP masked in {STUB_LO:#x}..{STUB_HI:#x}]: {len(stub_events)} events")
P(f"   RIP histogram (top6): {dict(stub_rip_hist.most_common(6))}")
P(f"   CR2 histogram (top6): {dict(stub_cr2_hist.most_common(6))}")
P(f"#UD RIP histogram (top8): {dict(ud_rips.most_common(8))}")

for c2 in (0xc08, 0x2718D834D1CC):
    P(f"\n--- event CR2={c2:#x} first full regs ---")
    r = first_regs.get(c2)
    if r:
        for k in ("RAX","RBX","RCX","RDX","RSI","RDI","RBP","RSP","R8","R9","R10","R11","R12","R13","R14","R15","CR3","CCS","CCD","CCO"):
            if k in r: P(f"   {k}={r[k]}")
        for nm in ("RBX","RDI","RSI","RCX","R12","R13"):
            if nm in r:
                try:
                    va = int(r[nm],16); s = cstr(va)
                    if s: P(f"   {nm}={va:#x} -> STRING {s[:90]!r}")
                except Exception: pass
    else:
        P("   (not captured)")

P("\n--- raw bytes at thunk site 0x9e65a310..0x9e65a380 ---")
b = img_bytes(0x9E65A310, 0x70)
P("   " + b.hex(" "))
P("\n--- disasm thunk 0x9e65a310..0x9e65a380 ---")
for l in disasm(0x9E65A310, 0x70): P(l)

P("\n--- disasm stub around event-#3 RIP 0x9e64482c (0x9e6447c0..0x9e644880) ---")
for l in disasm(0x9E6447C0, 0xC0): P(l)

P("\n--- disasm 0x9ef0d5a0..0x9ef0d960 (phase3 site + 2nd #GP site) ---")
for l in disasm(0x9EF0D5A0, 0x100, limit=48): P(l)

P("\n--- disasm panic/vpanic 0x9e83f8c0 ---")
for l in disasm(0x9E83F8C0, 0xC0): P(l)

P("\n--- .data scans for trash pointer values ---")
for val, label in [
    (0x3191250, "0x3191250 (truncated)"),
    (0xFFFF8E7703191250, "full DMAP 0xffff8e7703191250"),
    (0x2718D834D1CC, "0x2718d834d1cc"),
    (0x000000009F774820, "truncated 0x9f774820"),
    (0x0000000000000C08, "0xc08"),
]:
    needle = struct.pack("<Q", val)
    hits = []
    off = data_img.find(needle)
    while off != -1 and len(hits) < 10:
        hits.append(D_VA + off); off = data_img.find(needle, off+1)
    P(f"  {label}: {len(hits)} hits -> " + (", ".join(hex(h) for h in hits) if hits else "none"))
    off = text_img.find(needle); th = []
    while off != -1 and len(th) < 5:
        th.append(T_VA + off); off = text_img.find(needle, off+1)
    if th: P(f"     .text hits: " + ", ".join(hex(h) for h in th))

P("\n--- RBX struct at 0xa1971060 (mtx layout) ---")
b = img_bytes(0xA1971060, 0x28)
for i in range(0, 0x28, 8):
    q = struct.unpack("<Q", b[i:i+8])[0]
    P(f"   +{i:#04x}: {q:#018x}" + (f"  ptr" if 0xFFFFFFFF9F000000 <= q < 0xFFFFFFFFA3000000 else ""))
namep = struct.unpack("<Q", b[0:8])[0]
if 0xFFFFFFFF9E000000 <= namep < 0xFFFFFFFFA3000000:
    P(f"   name -> {cstr(namep)!r}")

P("\n--- .data at 0xa1b5bfa8 (dispatcher global) & 0xa1f95fb0 ---")
for va in (0xA1B5BFA8, 0xA1F95FB0):
    q = struct.unpack("<Q", img_bytes(va, 8))[0]
    P(f"   {va:#x}: {q:#018x}")

P("\n--- strings: trap-path pointers from event 31486 ---")
for va in (0x9EEF7A01, 0x9EEF7A20, 0x9EEF7A70, 0x9F65DAE4, 0x9F6E8550):
    P(f"   {va:#x}: {cstr(va)!r}   hex={img_bytes(va,16).hex()}")

P("\n--- panic-fn fmt strings (lea targets in 0x9e7df2f0..0x9e7df378) ---")
for va in (0x9F6C75C6, 0x9F7249CE, 0x9EAD768F, 0x9F64D9D0):
    try: P(f"   {va:#x}: {cstr(va)!r}")
    except Exception as e: P(f"   {va:#x}: ERR")

open(OUT, "w").write("\n".join(report) + "\n")
print(f"\n[-> {OUT}]", file=sys.stderr)
