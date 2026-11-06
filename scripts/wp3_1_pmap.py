#!/usr/bin/env python3
"""WP3-STEP 1: pmap_bootstrap (0xffffffff9eccbf50) full dissection.

Questions (user's spec):
  A) How much physical memory above physfree (0x22225000) does it consume
     for new kernel page tables, and at which VAs does it touch them
     (KERNBASE+phys, or Direct Map 0xffff...)?  -> initial-PT coverage contract
  B) What is the meaning of [0xffffffffa1f38fe0] (live 0xffffc67fffd33020)
     and of `mov qword ptr [rax], 0` + CR3 reload @0x9edf9c8e?
  C) The exact DMAP base / KERNBASE derivation constants.
Output: download/ps5_wp3/wp3_1_pmap_bootstrap.txt (+ console summary)
"""
import sys, struct
sys.path.insert(0, "./scripts")
from wp1_lib import (disasm, read, read_u64, read_u32, cstr, rip_target,
                     va2off, DATA_BASE, DATA_END, TEXT_BASE, TEXT_END,
                     CODE_BASE, in_text, in_data)

OUT = open("./download/ps5_wp3/wp3_1_pmap_bootstrap.txt", "w")

# known-name registry (grown across WP1/WP2/WP3)
KNOWN = {
    0xffffffff9e642a90: "btext",
    0xffffffff9e6428f0: "resumectx",
    0xffffffff9e6427d0: "savectx",
    0xffffffff9e642a40: "ap_entry",
    0xffffffff9e64d410: "printf",
    0xffffffff9f08aa10: "panic",
    0xffffffff9e9261f0: "mi_startup",
    0xffffffff9edf8790: "machine_init",
    0xffffffff9edf9310: "memmap_builder(main part of machine_init tail)",
    0xffffffff9eccbf50: "pmap_bootstrap",
    0xffffffff9e86dd70: "getenv",
    0xffffffff9e648ff0: "bzero?",
    0xffffffff9f006a20: "hc31_wrapper",
}

def note(s):
    OUT.write(s + "\n")

def annotate(ins):
    """Produce annotation text for one instruction."""
    ann = []
    t = rip_target(ins)
    if t is not None:
        s = cstr(t)
        if s:
            ann.append(f"str '{s}'")
        elif in_data(t):
            v64 = read_u64(t)
            v32 = read_u32(t)
            if v64 is not None and v64 != 0:
                ann.append(f"->data 0x{t:x} live_u64=0x{v64:x}")
        elif in_text(t):
            ann.append(f"->text 0x{t:x}")
    # call targets
    if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
        tgt = int(ins.op_str, 16)
        if tgt in KNOWN:
            ann.append("= " + KNOWN[tgt])
    # absolute low-phys accesses
    if "ptr [0x" in ins.op_str and "0xffffffff" not in ins.op_str:
        ann.append("LOW-PHYS access!")
    # paging-relevant
    if ins.mnemonic in ("mov",) and (", cr3" in ins.op_str or "cr3," in ins.op_str):
        ann.append("*** CR3 ***")
    if ins.mnemonic == "invlpg":
        ann.append("*** INVLPG ***")
    if ins.mnemonic in ("wrmsr", "rdmsr"):
        ann.append(f"*** {ins.mnemonic.upper()} ***")
    if ins.mnemonic == "vmmcall":
        ann.append("*** VMMCALL ***")
    if ins.mnemonic in ("lgdt", "lidt", "ltr", "sgdt", "sidt"):
        ann.append(f"*** {ins.mnemonic.upper()} ***")
    return " | ".join(ann)

def dump_func(va, name, maxbytes=0x2000, maxins=2000):
    note("=" * 100)
    note(f"FUNCTION {name} @ 0x{va:x}")
    note("=" * 100)
    n_ins = 0
    for ins in disasm(va, maxbytes, maxins):
        a = annotate(ins)
        line = f"0x{ins.address:x}  {ins.bytes.hex():<24} {ins.mnemonic} {ins.op_str}"
        if a:
            line += f"    ; {a}"
        note(line)
        n_ins += 1
        if ins.mnemonic == "ret":
            break
    note(f"[{n_ins} instructions]")

# ---------------- main ----------------
note("WP3-STEP1: pmap_bootstrap dissection — 13.60 kernel dump")
note("physfree at entry = 0x22225000; page size 0x4000 (16KB); KERNBASE=0xffffffff9e3f0000")
note("")

dump_func(0xffffffff9eccbf50, "pmap_bootstrap", maxbytes=0x3000)

# also dump the small helper that reads gb offset & delta (0x9edf92f0)
dump_func(0xffffffff9edf92f0, "gb_offset_helper", maxbytes=0x40)

OUT.close()
print("written; now scanning for key patterns...")

# ---- pattern scan over pmap_bootstrap ----
txt = open("./download/ps5_wp3/wp3_1_pmap_bootstrap.txt").read()
import re
summary = []
summary.append("KEY PATTERN SCAN in pmap_bootstrap:")
for pat, label in [
    (r"mov qword ptr \[rip [^\]]*\], 0x[0-9a-f]+", "rip-rel qword store const"),
    (r"shl \w+, 0x1e", "<<30 (GB shift)"),
    (r"shl \w+, 0xc\b", "<<12 (4K shift)"),
    (r"shr \w+, 0x1e", ">>30"),
    (r"0xffffc[0-9a-f]+", "DMAP-ish const"),
    (r"cr3", "CR3 op"),
    (r"invlpg", "INVLPG"),
    (r"call 0x[0-9a-f]+", "calls"),
]:
    hits = re.findall(pat, txt)
    summary.append(f"  {label}: {len(hits)}")
print("\n".join(summary))
