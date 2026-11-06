#!/usr/bin/env python3
"""WP11 Phase C — locate the function containing the crash at 0x9e8b6c71,
disassemble it from its prologue, and identify r13 (the lock word)."""
import capstone

DUMP = "./ps5/dump13/kernel-13.60-live.bin"
KTEXT = 0x9E3F0000
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
img = open(DUMP, "rb").read()

CRASH = 0xFFFFFFFF9E8B6C71
CRASH_BYTES = bytes.fromhex("418b8600040000")

lo = CRASH - 0x1000
off = lo - KTEXT
window = img[off:off + (CRASH - lo) + 16]

# find function boundaries: padding (cc cc / 0f 1f 44 0f 00 / 66 0f 1f...) between functions
cands = []
i = 0
while i < len(window) - 1:
    b = window[i]
    nxt = window[i + 1] if i + 1 < len(window) else 0
    # cc cc (int3 pad) or ret+cc or nop-pad end followed by new code
    if b == 0xCC and nxt == 0xCC:
        j = i
        while j < len(window) and window[j] == 0xCC:
            j += 1
        cands.append(lo + j)
        i = j
        continue
    i += 1

valid = []
for c in cands:
    code = img[c - KTEXT:CRASH - KTEXT + 16]
    for ins in md.disasm(code, c):
        if ins.address == CRASH:
            if ins.bytes == CRASH_BYTES:
                valid.append(c)
            break

print("candidate function starts:", [hex(v) for v in valid])
start = max(valid) if valid else None
print(f"function start = {start and hex(start)}")

if start:
    print()
    code = img[start - KTEXT:CRASH - KTEXT + 0x40]
    for ins in md.disasm(code, start):
        note = ""
        if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
            note = "  ; fn"
        print(f"{ins.address:#018x}  {ins.bytes.hex():<24} {ins.mnemonic} {ins.op_str}{note}")
        if ins.address > CRASH:
            break
