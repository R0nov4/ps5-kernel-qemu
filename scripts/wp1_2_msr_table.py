#!/usr/bin/env python3
"""WP1 item 2 — complete MSR usage table for the PS5 13.60 kernel.

Method (no guessing):
  A) byte-scan whole text for `0F 30` (wrmsr) / `0F 32` (rdmsr);
  B) each raw site is verified by back-sweep alignment AND must show an ECX
     definition (mov ecx,imm / xor ecx / mov ecx,reg / mov ecx,[mem]) inside the
     aligned window reaching the site -> sites without ECX setup are flagged
     suspicious (byte patterns inside other instructions);
  C) per verified site: ECX value (const / dynamic source), containing function
     (global call-target map), the function's referenced strings (file paths,
     panic/log formats) -> subsystem attribution;
  D) aggregate per MSR number: n_rd, n_wr, direction class, ECX kinds, functions,
     string evidence.
Outputs: download/ps5_wp1/wp1_2_msr.json / .txt
"""
import sys, os, json, struct, re
sys.path.insert(0, "./scripts")
import wp1_lib as L
from collections import defaultdict

OUT_DIR = "./download/ps5_wp1"
os.makedirs(OUT_DIR, exist_ok=True)
REP = []
def P(s=""):
    print(s)
    REP.append(s)

ECX_PATTERNS = {
    b"\xb9": "mov ecx, imm32",
    b"\x31\xc9": "xor ecx, ecx",
    b"\x89\xc8": "mov ecx, eax",
    b"\x8b\xc8": "mov ecx, eax",
    b"\x8b\x0d": "mov ecx, [rip+m]",
    b"\x8b\x4d": "mov ecx, [rbp+..]",
    b"\x8b\x4b": "mov ecx, [rbx+..]",
    b"\x8b\x8b": "mov ecx, [rbx+..]",
    b"\x8b\x8d": "mov ecx, [rbp+..]",
    b"\x44\x8b\xc9": "mov r9d, ecx",
}

def sweep_to_hit(hoff, maxback=48, maxins=72):
    """Find an aligned instruction stream that lands exactly on hit offset.
    Returns (ok, window_bytes) — prefers the DEEPEST (longest) sweep for context."""
    best = None
    for back in range(1, maxback + 1):
        s = hoff - back
        if s < 0:
            break
        pos = s
        cnt = 0
        ok = False
        for ins in L.md.disasm(L.text[s:hoff + 8], L.TEXT_BASE + s):
            if ins.address < L.TEXT_BASE + hoff and ins.address + ins.size > L.TEXT_BASE + hoff:
                break
            if ins.address == L.TEXT_BASE + hoff:
                ok = True
                break
            if ins.address > L.TEXT_BASE + hoff:
                break
            cnt += 1
            if cnt > maxins:
                break
        if ok:
            best = L.text[s:hoff]      # keep the LONGEST aligned window
    return (best is not None), best

# ---- function-anchored disassembly cache (rigorous alignment + full ECX tracking) ----
_fn_disasm_cache = {}
def fn_insns(fstart, fend_cap=0x4000):
    """Cached linear disasm of a function; list of capstone insns."""
    if fstart in _fn_disasm_cache:
        return _fn_disasm_cache[fstart]
    fend = L.containing_function(fstart)[1] or fstart + 0x200
    insns = L.disasm(fstart, min(fend, fstart + fend_cap) - fstart, maxins=4000)
    _fn_disasm_cache[fstart] = insns
    return insns

def site_context(va):
    """Try function-anchored alignment first (rigorous), else deepest back-sweep.
    Returns (quality, insns_before) — instructions decoded strictly before va,
    ending exactly at va (i.e., the instruction at va begins a true boundary)."""
    fstart, _ = L.containing_function(va)
    if fstart is not None:
        insns = fn_insns(fstart)
        upto = [i for i in insns if i.address < va]
        if upto and upto[-1].address + upto[-1].size == va:
            return "fn-anchored", upto
    hoff = L.va2off(va)
    ok, window = sweep_to_hit(hoff)
    if ok:
        wva = va - len(window)
        upto = list(L.md.disasm(window, wva))
        return "back-sweep", upto
    return None, None

def ecx_from_context(upto):
    """Last ECX/RCX-defining instruction before the site. PS5 kernel sets MSR index
    via BOTH 32-bit `mov ecx, imm` AND 64-bit `mov rcx, imm` / `movabs rcx, imm`
    (observed: mov rcx,0x1dd and movabs rcx,0xc0000110 in hammer_time)."""
    last = None
    for ins in upto:
        m, o = ins.mnemonic, ins.op_str
        if m in ("mov", "movabs") and (o.startswith("ecx, ") or o.startswith("rcx, ")):
            src = o.split(", ", 1)[1]
            if src.startswith("0x") or src.lstrip("-").isdigit():
                last = ("const", int(src, 0) & 0xFFFFFFFF, f"{m} {'rcx' if o.startswith('rcx') else 'ecx'}, {src}")
            else:
                last = ("dynamic", None, f"{m} {o}")
        elif m == "xor" and o.replace(" ", "") in ("ecx,ecx", "rcx,rcx"):
            last = ("const", 0, f"xor {o.replace(' ','')}")
        elif m in ("movzx", "movsx") and (o.startswith("ecx, ") or o.startswith("rcx, ")):
            last = ("dynamic", None, f"{m} {o}")
    return last or ("none", None, "no ECX def before site (same function)")

# ---------------- A+B: scan + verify ----------------
P("=" * 100)
P("WP1-2: MSR SITE SCAN (rdmsr 0F32 / wrmsr 0F30) — verified + ECX-resolved")
P("=" * 100)
sites = []
for pat, mnem, direction in ((b"\x0f\x32", "rdmsr", "R"), (b"\x0f\x30", "wrmsr", "W")):
    i = 0
    while True:
        i = L.text.find(pat, i)
        if i == -1:
            break
        va = L.TEXT_BASE + i
        if L.in_code(va):                     # only real-code region
            sites.append((va, mnem, direction))
        i += 1
P(f"\nraw sites in code region: {len(sites)} "
  f"(rdmsr {sum(1 for s in sites if s[2]=='R')}, wrmsr {sum(1 for s in sites if s[2]=='W')})")

verified, rejected = [], []
for va, mnem, direction in sites:
    quality, upto = site_context(va)
    if quality is None:
        rejected.append((va, mnem, "no alignment"))
        continue
    ins0 = L.disasm(va, 4, maxins=1)
    if not ins0 or ins0[0].mnemonic != mnem:
        rejected.append((va, mnem, "decode mismatch"))
        continue
    kind, val, txt = ecx_from_context(upto)
    verified.append({"va": va, "mnem": mnem, "dir": direction, "quality": quality,
                     "ecx_kind": kind, "ecx_val": val, "ecx_text": txt})
P(f"verified: {len(verified)}   rejected: {len(rejected)}")
P(f"  fn-anchored: {sum(1 for v in verified if v['quality']=='fn-anchored')}, "
  f"back-sweep-only: {sum(1 for v in verified if v['quality']=='back-sweep')}")
P(f"  verified with ECX-kind 'none': {sum(1 for v in verified if v['ecx_kind']=='none')}"
  f" (flagged: possibly false positive OR ECX set via uncommon path)")

# ---------------- C: context per site ----------------
func_cache = {}
def func_ctx(fstart):
    if fstart in func_cache:
        return func_cache[fstart]
    fend = L.containing_function(fstart)[1] or fstart + 0x200
    strings = L.function_strings(fstart, fend)
    files = sorted(set(s for _, _, s in strings if "/" in s and (".c" in s or ".h" in s)))
    fmts = sorted(set(s for _, _, s in strings if "%" in s))[:8]
    idents = sorted(set(s for _, _, s in strings
                        if L.looks_like_name(s) and "/" not in s and "%" not in s))[:10]
    func_cache[fstart] = (fend, files, fmts, idents)
    return func_cache[fstart]

for v in verified:
    fstart, fend = L.containing_function(v["va"])
    v["func"] = fstart
    if fstart is not None:
        fend, files, fmts, idents = func_ctx(fstart)
        v["func_end"] = fend
        v["files"] = files
        v["fmts"] = fmts
        v["idents"] = idents

# ---------------- D: aggregate per MSR ----------------
P("\n" + "=" * 100)
P("PER-MSR AGGREGATE (direction, sites, functions, subsystem evidence)")
P("=" * 100)
agg = defaultdict(lambda: {"R": 0, "W": 0, "sites": [], "funcs": set(),
                            "files": set(), "idents": set(), "ecx": set()})
for v in verified:
    if v["ecx_kind"] == "const":
        key = v["ecx_val"]
        agg[key]["ecx"].add(f"const 0x{v['ecx_val']:X}")
    else:
        key = ("dyn", v["ecx_text"])
        agg[key]["ecx"].add(v["ecx_kind"])
    a = agg[key]
    a[v["dir"]] += 1
    a["sites"].append(v["va"])
    if v.get("func"):
        a["funcs"].add(v["func"])
    for f in v.get("files", []):
        a["files"].add(f)
    for s in v.get("idents", []):
        a["idents"].add(s)

P(f"\ndistinct MSR keys: {len([k for k in agg if isinstance(k,int)])} const + "
  f"{len([k for k in agg if isinstance(k,tuple)])} dynamic-source")

KNOWN = {
    0x10: "TSC", 0x1B: "IA32_APIC_BASE", 0xE7: "IA32_MPERF", 0xE8: "IA32_APERF",
    0x198: "IA32_PERF_STATUS", 0x199: "IA32_PERF_CONTROL", 0x19A: "IA32_CLOCK_MODULATION",
    0x19B: "IA32_THERM_INTERRUPT", 0x1A0: "IA32_MISC_ENABLE", 0x1D9: "IA32_DEBUGCTL",
    0x1DB: "LastBranch_FromIP0", 0x1DC: "LastBranch_ToIP0", 0x1DD: "LastBranch_Info? (non-std)",
    0x1DE: "LastBranch_TOS?",
    0x250: "MTRRfix64K_00000", 0x258: "MTRRfix16K_80000", 0x259: "MTRRfix16K_C0000",
    0x268: "MTRRfix4K_C0000", 0x269: "MTRRfix4K_C8000", 0x26A: "MTRRfix4K_D0000",
    0x26B: "MTRRfix4K_D8000", 0x26C: "MTRRfix4K_E0000", 0x26D: "MTRRfix4K_E8000",
    0x26E: "MTRRfix4K_F0000", 0x26F: "MTRRfix4K_F8000",
    0x277: "IA32_PAT", 0x2FF: "MTRRdefType",
    0x400: "MC0_CTL", 0x401: "MC0_STATUS", 0x402: "MC0_ADDR", 0x406: "MC1_CTL?",
    0x404: "MC1_CTL", 0x405: "MC1_STATUS", 0x408: "MC2_CTL", 0x409: "MC2_STATUS",
    0x40C: "MC3_CTL", 0x40D: "MC3_STATUS", 0x410: "MC4_CTL", 0x411: "MC4_STATUS",
    0x414: "MC5_CTL", 0x415: "MC5_STATUS", 0x418: "MC6_CTL", 0x419: "MC6_STATUS",
    0x480: "MTRRphysBase0", 0x481: "MTRRphysMask0", 0x482: "MTRRphysBase1",
    0x483: "MTRRphysMask1", 0x48B: "MTRRphysBase?", 0x48C: "MTRRphysMask?",
    0x48D: "MTRRphysBase?", 0x48E: "MTRRphysMask?", 0x48F: "MTRRphysBase?",
    0x490: "MTRRphysMask?",
    0xC0000080: "EFER", 0xC0000081: "STAR", 0xC0000082: "LSTAR", 0xC0000083: "CSTAR",
    0xC0000084: "FMASK/SFMASK", 0xC0000100: "FS_BASE", 0xC0000101: "GS_BASE",
    0xC0000102: "KERNEL_GS_BASE", 0xC0000103: "TSC_AUX",
    0xC0000010: "AMD_SYSCFG", 0xC000001F: "AMD_HWCR", 0xC0000020: "AMD_NB_CFG",
    0xC0000041: "AMD_IC_CFG", 0xC0000042: "AMD_DC_CFG", 0xC0000048: "AMD_VM_CR",
    0xC000004A: "AMD_SMM_CTL", 0xC000004B: "AMD_VM_HSAVE_PA", 0xC0000044: "AMD_MC4_CTL?",
    0xC000010F: "AMD_??_0x10F", 0xC0004000: "AMD_?? (MCA config?)", 0xC0004600: "AMD_SMM_ADDR",
    0xC000F800: "AMD_??_F800", 0xC000C000: "AMD_??_C000", 0xC0009000: "AMD_??_9000",
    0xC000FFFF: "AMD_??_FFFF", 0xC0000063: "AMD_??_0063", 0xC0000039: "AMD_SPEC_CTRL?",
    0xC000003E: "AMD_LS_CFG?",
    0xC0010010: "AMD_SYS_CFG", 0xC0010015: "AMD_MC4_CTL?",
    0xC0010016: "AMD_IORR_BASE0", 0xC0010017: "AMD_IORR_MASK0",
    0xC0010018: "AMD_IORR_BASE1", 0xC0010019: "AMD_IORR_MASK1",
    0xC001001A: "AMD_TOP_MEM", 0xC001001D: "AMD_TOP_MEM2", 0xC001001F: "AMD_??_001F",
    0xC0010041: "AMD_MC0_CTL_MASK?", 0xC0010042: "AMD_MC1_CTL_MASK?",
    0xC0010044: "AMD_MC4_CTL_MASK?",
    0xC0010055: "AMD_SMM_MASK?", 0xC0010061: "AMD_DBGCTL", 0xC0010062: "AMD_DBG_STATUS",
    0xC0010063: "AMD_LASTBRANCH_FROM?", 0xC0010064: "AMD_LBR stack (0x64-0x6B)",
    0xC0010114: "AMD_??_0114 (C-state?)",
    0xC0011000: "AMD_LS_CFG", 0xC0011001: "AMD_IC_CFG", 0xC0011002: "AMD_DC_CFG",
    0xC0011004: "AMD_??_1004", 0xC0011005: "AMD_??_1005",
    0xC0011019: "AMD_??_1019", 0xC001101A: "AMD_??_101A", 0xC001101B: "AMD_??_101B",
    0xC0011024: "AMD_??_1024", 0xC0011025: "AMD_??_1025", 0xC0011026: "AMD_??_1026",
    0xC0011027: "AMD_??_1027", 0xC0011029: "AMD_??_1029",
    0xC0011033: "AMD_??_1033 (Zen2?)", 0xC0011074: "AMD_??_1074",
    0xC0011076: "AMD_??_1076", 0xC0011077: "AMD_??_1077", 0xC0011083: "AMD_??_1083",
    0xC00110AD: "AMD_??_10AD (Zen2 resync?)",
    0xC0019901: "AMD_??_9901 (Zen?)", 0xC0019B01: "AMD_??_9B01 (Zen?)",
    0xC0010200: "AMD_PERF_CTL[0]", 0xC0010201: "AMD_PERF_CTR[0]",
    0xC0010202: "AMD_PERF_CTL[1]", 0xC0010203: "AMD_PERF_CTR[1]",
    0xC0010204: "AMD_PERF_CTL[2]", 0xC0010205: "AMD_PERF_CTR[2]",
    0xC0010206: "AMD_PERF_CTL[3]", 0xC0010207: "AMD_PERF_CTR[3]",
    0xC0010208: "AMD_PERF_CTL[4]", 0xC0010209: "AMD_PERF_CTR[4]",
    0xC001020A: "AMD_PERF_CTL[5]", 0xC001020B: "AMD_PERF_CTR[5]",
    0xC0010230: "AMD_??_0230 (Zen IBS?)", 0xC0010231: "AMD_??_0231",
    0xC0010232: "AMD_??_0232", 0xC0010233: "AMD_??_0233",
    0xC0010240: "AMD_??_0240", 0xC0010241: "AMD_??_0241",
    0xC0010190: "AMD_??_0190", 0xC0010191: "AMD_??_0191",
    0x811: "AMD_??_0811 (MCA mask?)", 0x812: "AMD_??_0812", 0x813: "AMD_??_0813",
    0x814: "AMD_??_0814", 0x815: "AMD_??_0815", 0x816: "AMD_??_0816",
    0x817: "AMD_??_0817",
    0x838: "AMD_MCi_ADDR?", 0x841: "AMD_MCi_STATUS?", 0xC0010053: "AMD_SMM_ADDR",
}

rows = []
for key in sorted(agg.keys(), key=lambda k: (isinstance(k, tuple), k if isinstance(k,int) else 0)):
    a = agg[key]
    nr = key if isinstance(key, int) else None
    nR, nW = a["R"], a["W"]
    if nR and nW:
        d = "R+W"
    elif nR:
        d = "R"
    else:
        d = "W"
    label = KNOWN.get(nr, "CUSTOM/UNKNOWN") if nr is not None else f"dynamic ({key[1]})"
    files = sorted(a["files"])
    idents = sorted(a["idents"])
    rows.append({"msr": (f"0x{nr:08X}" if nr is not None else "dyn"),
                 "dir": d, "nR": nR, "nW": nW,
                 "ecx": sorted(a["ecx"]),
                 "n_sites": len(a["sites"]),
                 "site_first": f"0x{min(a['sites']):x}",
                 "n_funcs": len(a["funcs"]),
                 "funcs": [f"0x{f:x}" for f in sorted(a["funcs"])[:6]],
                 "files": files[:4], "idents": idents[:8],
                 "label": label})
    P(f"\nMSR {rows[-1]['msr']:>12s} [{label}]  dir={d}  sites={len(a['sites'])} "
      f"(R={nR},W={nW})  funcs={rows[-1]['n_funcs']}  first_site={rows[-1]['site_first']}")
    if files:
        P(f"    files: {files[:3]}")
    if idents:
        P(f"    ident evidence: {idents[:6]}")

json.dump({"verified_sites": [{"va": hex(v["va"]), "dir": v["dir"], "ecx": v["ecx_text"],
                               "func": hex(v["func"]) if v.get("func") else None}
                              for v in verified],
           "aggregate": rows},
          open(f"{OUT_DIR}/wp1_2_msr.json", "w"), indent=1)
open(f"{OUT_DIR}/wp1_2_msr.txt", "w").write("\n".join(REP))
P(f"\nsaved -> {OUT_DIR}/wp1_2_msr.json / .txt")
