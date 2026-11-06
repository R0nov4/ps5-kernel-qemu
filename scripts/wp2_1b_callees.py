#!/usr/bin/env python3
"""WP2 STEP 1b — disassemble machine_init's key callees to complete the Loader Contract.
Focus: RAX chain (thread0 stack/pcb), metadata parse (phys 0x22270), RAM size,
subcall .data sensitivities.
"""
import sys, struct
sys.path.insert(0, "./scripts")
import wp1_lib as L

TARGETS = [
    ("0x9ee40ac0", 0xFFFFFFFF9EE40AC0, 0xC0, "RAX-chain: fn(&thread0) -> [0xa1978c58] (RETURNED RSP)"),
    ("0x9ee40a80", 0xFFFFFFFF9EE40A80, 0xC0, "RAX-chain sibling: fn(&thread0) -> B; then fn3(B,0x400)"),
    ("0x9e648ff0", 0xFFFFFFFF9E648FF0, 0x100, "alloc/map fn called 2x (virtual_avail,0x4000) & (B,0x400)"),
    ("0x9eafddd0", 0xFFFFFFFF9EAFDDD0, 0x120, "metadata parse fn(rdi=[0xa1e251c0]=0x22270 phys)"),
    ("0x9ef80000", 0xFFFFFFFF9EF80000, 0x100, "subcall #1 (very early, before hook check)"),
    ("0x9e65f630", 0xFFFFFFFF9E65F630, 0x100, "cpu-init hook fn(arg1<<12) -> [rbp-0x38]"),
    ("0x9eafdbe0", 0xFFFFFFFF9EAFDBE0, 0x80, "subcall after cpu-hook"),
    ("0x9e8b8150", 0xFFFFFFFF9E8B8150, 0x100, "pcpu init (0xa1fb8f00, 0, 0x980)"),
    ("0x9e8b81d0", 0xFFFFFFFF9E8B81D0, 0x100, "call(virtual_avail, 0) — pmap-bootstrap-ish"),
    ("0x9e8b7f30", 0xFFFFFFFF9E8B7F30, 0x80, "call before mtx_init quartet"),
    ("0x9e649a50", 0xFFFFFFFF9E649A50, 0x80, "call(&GDTR @0xa1fa89e0) — lgdt wrapper?"),
    ("0x9edf9310", 0xFFFFFFFF9EDF9310, 0x140, "local helper fn([rbp-0x38])"),
    ("0x9edfa0b0", 0xFFFFFFFF9EDFA0B0, 0x140, "local helper fn #2"),
]

for name, va, n, desc in TARGETS:
    print("=" * 100)
    print(f"CALLEE {name} — {desc}")
    print("=" * 100)
    for ins in L.disasm(va, n, maxins=60):
        ann = []
        t = L.rip_target(ins)
        if t is not None:
            ann.append(f"-> 0x{t:x}")
            if L.in_data(t):
                s = L.cstr(t, 56)
                if s:
                    ann.append(f"str {s!r}")
                else:
                    v = L.read_u64(t)
                    ann.append(f"u64=0x{v:016x}" if v is not None else "")
        if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
            try:
                tgt = int(ins.op_str, 16)
                if L.in_code(tgt):
                    ann.append(f"CALLTGT")
            except ValueError:
                pass
        for special in ("rdmsr", "wrmsr", "lgdt", "lidt", "sgdt", "sidt", "ltr", "str",
                        "cli", "sti", "hlt", "cpuid", "invd", "wbinvd", "wrcr3", "movcr3"):
            if ins.mnemonic == special:
                ann.append("### " + special.upper())
        print(f"  0x{ins.address:x}  {ins.bytes.hex():<20s} {ins.mnemonic} {ins.op_str}"
              + ("    ; " + " | ".join(ann) if ann else ""))
    print()
