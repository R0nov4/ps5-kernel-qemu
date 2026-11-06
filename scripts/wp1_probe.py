"""WP1 probe: resolve key strings & contexts discovered in the hypercall analysis."""
import sys, json, struct
sys.path.insert(0, "./scripts")
import wp1_lib as L

print("== key string probes ==")
for va, why in [
    (0xFFFFFFFF9F7724EE, "shared __FILE__ of hc 0xB / hc 13 wrappers"),
    (0xFFFFFFFF9F6E4D2B, "hc 0xB log arg (rcx)"),
    (0xFFFFFFFF9F787052, "hc 0xB log arg (r8)"),
]:
    print(f"  0x{va:x} [{why}]")
    print(f"    -> {L.cstr(va, 160)!r}")

print("\n== u32 table at 0x9f7a4938 (hc-13 dump entity ids, 16 entries) ==")
for i in range(16):
    v = L.read_u32(0xFFFFFFFF9F7A4938 + 4 * i)
    print(f"    [{i:2d}] 0x{v:08x}")

print("\n== data around the single DATA-pointer to wrapper hc15 (0x9f4bf243) ==")
blob = L.read(0xFFFFFFFF9F4BF200, 0xA0)
print("  hex 0x9f4bf200..0x9f4bf2a0:")
for off in range(0, 0xA0, 16):
    print(f"    0x{0xFFFFFFFF9F4BF200+off:x}: {blob[off:off+16].hex(' ')}  "
          f"{''.join(chr(c) if 32 <= c <= 126 else '.' for c in blob[off:off+16])}")
for d in range(-3, 4):
    va = 0xFFFFFFFF9F4BF243 + 8 * d - (8 * 3)  # walk qwords around, aligned to 0x...240
    pass
# strings near it
for va in range(0xFFFFFFFF9F4BF1C0, 0xFFFFFFFF9F4BF300, 1):
    s = L.cstr(va, 64)
    if s and len(s) >= 5:
        print(f"    str @0x{va:x}: {s!r}")

print("\n== caller 0x9eaa55a0 (calls hc 4, hc 31, hc 5) full disasm ==")
print(L.disasm_str(0xFFFFFFFF9EAA55A0, 0xB0, maxins=60))

print("\n== identify helper callees of the wrappers ==")
for va, hint in [
    (0xFFFFFFFF9EFEBC30, "10-arg call inside hc 0xB wrapper (log-like?)"),
    (0xFFFFFFFF9E8B78B0, "mtx_lock_flags-like (rdi,0,FILE,LINE)"),
    (0xFFFFFFFF9EAA77C0, "second call after lock"),
    (0xFFFFFFFF9E8B7520, "third call (rdi+0x18)"),
    (0xFFFFFFFF9E85E1E0, "delay-like in hc 0xA retry (edi=10)"),
]:
    print(f"  -- 0x{va:x} [{hint}] --")
    print(L.disasm_str(va, 0x60, maxins=18))

print("\n== wrapper hc15 (0x9f006ee0) and its data-ptr neighborhood ==")
print(L.disasm_str(0xFFFFFFFF9F006EE0, 0x20, maxins=12))

print("\n== xref JSON: sites targeting 0x9f0071b0 (hc18) and 0x9f006c92 (multi-13) ==")
j = json.load(open("./download/ps5_wp1/wp1_1_hypercalls.json"))
for x in j["xrefs_call_jmp"]:
    t = int(x["target"], 16)
    if t in (0xFFFFFFFF9F0071B0, 0xFFFFFFFF9F006C92, 0xFFFFFFFF9F006C70):
        print(f"    {x['kind']} @0x{int(x['site'],16):x} -> 0x{t:x}")

print("\n== gap region 0x9f0070a6..0x9f0071b0 disasm (non-vmmcall funcs) ==")
print(L.disasm_str(0xFFFFFFFF9F0070A6, 0x110, maxins=70))
