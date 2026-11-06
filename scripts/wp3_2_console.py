#!/usr/bin/env python3
"""WP3-STEP 2: Console path discovery.
printf (0xffffffff9e64d410) -> kvprintf -> putchar -> cnputc -> cn_tab (consdev) -> device.
Find: which device, which MMIO/IO-port/memory buffer, which flags enable output.
"""
import sys, struct
sys.path.insert(0, "./scripts")
from wp1_lib import (disasm, read, read_u64, read_u32, cstr, rip_target,
                     va2off, in_data, in_text, DATA_BASE, DATA_END)

OUT = open("./download/ps5_wp3/wp3_2_console.txt", "w")
def note(s): OUT.write(s + "\n"); print(s)

KNOWN = {
    0xffffffff9e64d410: "printf",
    0xffffffff9f08aa10: "panic",
    0xffffffff9e648ff0: "bzero",
}

def dis(va, name, maxbytes=0x400, maxins=400, quiet=False):
    if not quiet:
        note("=" * 90)
        note(f"FUNC {name} @ 0x{va:x}")
    lines = []
    for ins in disasm(va, maxbytes, maxins):
        t = rip_target(ins); a = ""
        if t is not None:
            s = cstr(t)
            extra = ""
            if in_data(t):
                v = read_u64(t)
                if v: extra = f" live=0x{v:x}"
            a = f" ; -> 0x{t:x}" + (f" '{s}'" if s else "") + extra
        if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
            tgt = int(ins.op_str, 16)
            if tgt in KNOWN:
                a += f" ; = {KNOWN[tgt]}"
        line = f"0x{ins.address:x}  {ins.bytes.hex():<22} {ins.mnemonic} {ins.op_str}{a}"
        if not quiet:
            note(line)
        lines.append((ins, a))
        if ins.mnemonic == "ret":
            break
    return lines

# ---- printf ----
p = dis(0xffffffff9e64d410, "printf", 0x200)

# find calls inside printf
calls = []
for ins, a in p:
    if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
        calls.append(int(ins.op_str, 16))
note(f"\nprintf calls: {[hex(c) for c in calls]}")

# ---- vprintf-like (first callee that is not known) ----
for c in calls:
    if c in KNOWN: continue
    name = f"printf_callee_0x{c:x}"
    sub = dis(c, name, 0x300, quiet=True)
    subcalls = [int(i.op_str,16) for i,_ in sub if i.mnemonic=="call" and i.op_str.startswith("0x")]
    strs = [a for i,a in sub if "'" in a]
    note(f"\n  {name}: {len(sub)} ins, calls={[hex(x) for x in subcalls][:12]}, strings={[s for s in strs][:6]}")

OUT.close()
print("\n--- continuing interactively ---")
