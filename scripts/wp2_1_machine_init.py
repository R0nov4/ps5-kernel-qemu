#!/usr/bin/env python3
"""WP2 STEP 1 — full dissection of machine_init (0xffffffff9edf8790).

Outputs an annotated disassembly:
  - every RIP-relative target resolved (global VA + live value + string)
  - every absolute low-physical access ([0x9bf4c] style) marked PHYS
  - every direct call target marked
Goal: extract the byte-exact LOADER CONTRACT (what the QEMU loader must
place in low RAM so machine_init returns a valid kernel stack in RAX).
"""
import sys, struct, re
sys.path.insert(0, "./scripts")
import wp1_lib as L
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

MI = 0xFFFFFFFF9EDF8790

# ---- function bounds: next known function start after MI ----
fs = L.function_starts()
import bisect
i = bisect.bisect_right(fs, MI)
FSTART = fs[i-1] if fs[i-1] == MI else MI
# next distinct start strictly greater
FEND = fs[i]
print(f"machine_init bounds: [0x{FSTART:x}, next-start 0x{FEND:x})  size={FEND-FSTART} bytes")
# cap: also find 'ret' alignment heuristics later; disasm whole range
N = FEND - FSTART

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False

insns = []
for ins in md.disasm(L.read(MI, N), MI):
    insns.append(ins)
    if ins.address >= MI + N - 16:
        break
print(f"disassembled {len(insns)} instructions (raw region {N} bytes)")

# ---- annotation pass ----
PHYS_RE = re.compile(r"\[0x([0-9a-f]{1,9})\]")   # absolute short addresses (phys)
LOW = lambda a: 0 < a < 0x1000000                # low 16MB => physical (identity)

out = []
notes_phys = {}      # phys addr -> [(va, mnemonic, op)]
notes_calls = {}     # call target -> [vas]
notes_rip = {}       # rip target -> [vas]
notes_ret = []

for ins in insns:
    ann = []
    # 1. absolute physical accesses
    m = PHYS_RE.search(ins.op_str)
    if m and ins.mnemonic not in ("call", "jmp", "jo", "jno", "js", "jns", "je", "jne",
                                   "jb", "jae", "jbe", "ja", "jg", "jl", "jge", "jle",
                                   "jp", "jnp", "loop", "loopne", "loope"):
        a = int(m.group(1), 16)
        if LOW(a):
            ann.append(f"PHYS 0x{a:x}")
            notes_phys.setdefault(a, []).append((ins.address, ins.mnemonic, ins.op_str))
    # 2. rip-relative targets
    t = L.rip_target(ins)
    if t is not None:
        ann.append(f"RIP->0x{t:x}")
        notes_rip.setdefault(t, []).append(ins.address)
        if L.in_data(t):
            v = L.read_u64(t)
            s = L.cstr(t, 64)
            if s:
                ann.append(f"str {s!r}")
            else:
                ann.append(f"u64=0x{v:016x}" if v is not None else "u64=?")
        elif L.in_text(t):
            ann.append("-> text")
    # 3. direct calls/jmps rel32
    if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
        tgt = int(ins.op_str, 16)
        if L.in_code(tgt):
            ann.append(f"CALLTGT 0x{tgt:x}")
            if ins.mnemonic == "call":
                notes_calls.setdefault(tgt, []).append(ins.address)
    if ins.mnemonic in ("ret", "retf"):
        notes_ret.append(ins.address)
    b = ins.bytes.hex()
    out.append(f"0x{ins.address:x}  {b:<24s} {ins.mnemonic} {ins.op_str}"
               + ("    ; " + " | ".join(ann) if ann else ""))

with open("./download/ps5_wp2/machine_init_disasm.txt", "w") as f:
    f.write("\n".join(out))
print(f"wrote ./download/ps5_wp2/machine_init_disasm.txt ({len(out)} lines)")

# ---- summary tables ----
print("\n=== ABSOLUTE PHYSICAL ACCESSES (identity-mapped low RAM) ===")
for a in sorted(notes_phys):
    uses = notes_phys[a]
    kinds = set(f"{m} {o}" for _, m, o in uses)
    print(f"  phys 0x{a:x}: {len(uses)} refs  e.g. {list(kinds)[:3]}")

print("\n=== CALL TARGETS (unique, in call order) ===")
seen = []
for ins in insns:
    if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
        tgt = int(ins.op_str, 16)
        if L.in_code(tgt) and tgt not in seen:
            seen.append(tgt)
print(f"  {len(seen)} unique call targets:")
for tgt in seen:
    n = len(notes_calls.get(tgt, []))
    print(f"    0x{tgt:x}  ({n} calls)")

print(f"\n=== RETURNS: {len(notes_ret)} ===")
print("  " + ", ".join(hex(r) for r in notes_ret[:40]))

print("\n=== RIP TARGETS IN DATA (globals touched) ===")
gcount = 0
for t in sorted(notes_rip):
    if L.in_data(t):
        gcount += 1
print(f"  {gcount} distinct data globals referenced")
