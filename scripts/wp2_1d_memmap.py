#!/usr/bin/env python3
"""WP2 STEP 1d — full annotated disassembly of the memory-layout builder
0x9edf9310 (RAM size / physmem derivation) + cpu-init hook 0x9edf6a50.. +
raw-0x9bf4c/0x9bf54 consumers (0x9edfc070/0x9edfc090) + 0x9edf92f0 + 0x9edfa0b0.
"""
import sys, struct, re
sys.path.insert(0, "./scripts")
import wp1_lib as L

def dump(va, n, title):
    print("=" * 104)
    print(title)
    print("=" * 104)
    out = []
    for ins in L.disasm(va, n, maxins=2000):
        ann = []
        t = L.rip_target(ins)
        if t is not None:
            ann.append(f"->0x{t:x}")
            if L.in_data(t):
                s = L.cstr(t, 56)
                if s:
                    ann.append(f"str {s!r}")
                else:
                    v = L.read_u64(t)
                    if v is not None:
                        ann.append(f"val=0x{v:016x}")
            elif L.in_text(t):
                ann.append("(text)")
        m = re.search(r"\[0x([0-9a-f]{1,7})\]", ins.op_str)
        if m and ins.mnemonic not in ("call", "jmp", "je", "jne", "ja", "jb", "jg", "jl",
                                      "jae", "jbe", "jge", "jle", "js", "jns"):
            a = int(m.group(1), 16)
            if 0 < a < 0x1000000 and "gs:" not in ins.op_str and "fs:" not in ins.op_str:
                ann.append(f"*** PHYS 0x{a:x} ***")
        if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
            try:
                tgt = int(ins.op_str, 16)
                if L.in_code(tgt):
                    ann.append("CALLTGT")
            except ValueError:
                pass
        out.append(f"0x{ins.address:x}  {ins.bytes.hex():<22s} {ins.mnemonic} {ins.op_str}"
                   + ("    ; " + " | ".join(ann) if ann else ""))
    print("\n".join(out))
    print()

dump(0xFFFFFFFF9EDF9310, 0xD00, "MEMORY-LAYOUT BUILDER 0x9edf9310 (rdi=cpu-hook-result, rsi=physfree+0x4000)")
dump(0xFFFFFFFF9EDF6A50, 0x90, "CPU-INIT HOOK (thunk 0x9e65f630 -> here) — reads gb_offset & [0x9b6f4]")
dump(0xFFFFFFFF9EDFC070, 0x80, "raw_[0x9bf4c]/raw_[0x9bf54] consumer A (0x9edfc070)")
dump(0xFFFFFFFF9EDFC090, 0x80, "raw_[0x9bf4c]/raw_[0x9bf54] consumer B (0x9edfc090)")
dump(0xFFFFFFFF9EDF92F0, 0x60, "helper 0x9edf92f0 (reads gb_offset & [0x9b6f4])")
