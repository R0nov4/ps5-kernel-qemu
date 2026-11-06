"""Smoke test for wp1_lib + first look at text head & wrapper region."""
import sys
sys.path.insert(0, "./scripts")
import wp1_lib as L

print("== layout ==")
print(f"text  0x{L.TEXT_BASE:x} .. 0x{L.TEXT_END:x}  ({L.TEXT_SIZE:,} bytes)")
print(f"data  0x{L.DATA_BASE:x} .. 0x{L.DATA_END:x}  ({L.DATA_SIZE:,} bytes)")

# ---- head of text: how much real code before the 0xCC run? ----
head = L.text[:0x400]
print("\n== first 64 bytes of text (head) ==")
print(" ".join(f"{b:02x}" for b in head[:64]))

# find where the 0xCC run starts
i = 0
while i < L.TEXT_SIZE and L.text[i] != 0xCC:
    i += 1
print(f"\nfirst 0xCC byte at file off 0x{i:x} (VA 0x{L.TEXT_BASE + i:x})")
# verify CC run continues to CODE_BASE
cc_run = all(b == 0xCC for b in L.text[i:L.CODE_BASE - L.TEXT_BASE])
print(f"0xCC uniform from 0x{i:x} to CODE_BASE(0x{L.CODE_BASE:x}): {cc_run}")
# any non-CC byte inside the padding?
j = i
anomalies = []
while j < L.CODE_BASE - L.TEXT_BASE:
    if L.text[j] != 0xCC:
        anomalies.append(j)
        if len(anomalies) > 8:
            break
    j += 1
print(f"non-CC anomalies inside padding: {anomalies}")

print("\n== head disasm (offset 0, first 40 insns) ==")
print(L.disasm_str(L.TEXT_BASE, 0x300, maxins=40))

print("\n== first bytes at CODE_BASE (0xffffffff9e640000) ==")
print(L.disasm_str(L.CODE_BASE, 0x100, maxins=30))

# ---- wrapper region first look ----
W0, W1 = 0xFFFFFFFF9F006A10, 0xFFFFFFFF9F00720D
print(f"\n== wrapper region 0x{W0:x}..0x{W1:x} first 64 insns ==")
print(L.disasm_str(W0, 0x100, maxins=64))

# quick lib checks
fs = L.function_starts()
print(f"\nfunction-map starts: {len(fs):,}")
s, e = L.containing_function(0xFFFFFFFF9F006A80)
print(f"containing_function(0x9f006a80) = 0x{s:x}..0x{e:x}")
print("cstr('W:/Build...' probe):", L.cstr(0xFFFFFFFF9F6D0000 + 0x0))  # placeholder
