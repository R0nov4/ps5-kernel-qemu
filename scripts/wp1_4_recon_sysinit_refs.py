#!/usr/bin/env python3
"""WP1-fix recon: find all RIP-relative references to sysinit_set (0xffffffff9fe51fb0)
and sysuninit_set (0xffffffff9fe55070) => locate mi_startup.
Scans ALL rip-relative instruction forms (REX + opcode + modrm(mod=00,rm=101) + disp32),
plus movabs imm64 data-address loads.
"""
import sys, struct
sys.path.insert(0, "./scripts")
import wp1_lib as L

TARGETS = {
    0xFFFFFFFF9FE51FB0: "sysinit_set",
    0xFFFFFFFF9FE55068: "sysinit_set_END",
    0xFFFFFFFF9FE55070: "sysuninit_set",
    0xFFFFFFFF9FE57508: "sysuninit_set_END",
    0xFFFFFFFF9FE50000: "mod_metadata_set",
    0xFFFFFFFF9FE51FA8: "sysinit_set-8",
    0xFFFFFFFF9FE51FB8: "sysinit_set+8",
}

hits = []
t = L.text
n = len(t)
# REX-prefixed opcodes with disp32 rip-relative: lea(8d), mov(8b/89), cmp(3b/39), movzx family etc.
# generic: REX? [0F 38/3A?] op modrm(05) disp32
i = 0
while i < n - 8:
    b0 = t[i]
    pos = i
    # optional legacy prefixes (66 67 f2 f3)
    p = i
    while t[p] in (0x66, 0x67, 0xF2, 0xF3, 0x2E, 0x3E):
        p += 1
        if p - i > 3:
            break
    rex = None
    q = p
    if 0x40 <= t[q] <= 0x4F:
        rex = t[q]
        q += 1
    op = t[q]
    # handle two/three-byte opcodes (skip for simplicity unless 0F 1A etc.)
    if op == 0x0F:
        q += 1
        op2 = t[q]
        q += 1
        # only forms with modrm follow: treat any 0F xx with modrm
        modrm = t[q] if q < n else 0xFF
    else:
        q += 1
        modrm = t[q] if q < n else 0xFF
    if (modrm & 0xC7) == 0x05:  # mod=00 rm=101 => [rip+disp32]
        dpos = q + 1
        if dpos + 4 <= n:
            disp = struct.unpack_from("<i", t, dpos)[0]
            end = dpos + 4
            tgt = L.TEXT_BASE + end + disp
            if tgt in TARGETS:
                ok, _ = L.aligned_reachable(L.TEXT_BASE + pos, maxback=64, maxins=80)
                hits.append((pos, tgt, end - pos, ok))
    i = pos + 1

# movabs with imm64 == target
for tgt in TARGETS:
    pat = struct.pack("<Q", tgt)
    j = 0
    while True:
        j = t.find(pat, j)
        if j == -1:
            break
        va = L.TEXT_BASE + j
        if L.in_code(va):
            ok, _ = L.aligned_reachable(va - 7, maxback=64, maxins=80)  # movabs starts 2 bytes before imm
            hits.append((j - 2, tgt, 10, ok))
        j += 1

print(f"raw hits: {len(hits)}")
for pos, tgt, ln, ok in sorted(set(hits)):
    va = L.TEXT_BASE + pos
    fstart, _ = L.containing_function(va)
    ins = L.disasm(va, 12, maxins=1)
    s = f"{ins[0].mnemonic} {ins[0].op_str}" if ins else "?"
    print(f"  0x{va:x}  {s:<44s} -> {TARGETS[tgt]}  aligned={ok}  func=0x{fstart:x}" if fstart else
          f"  0x{va:x}  {s:<44s} -> {TARGETS[tgt]}  aligned={ok}  func=NONE(pre-CODE_BASE)")
