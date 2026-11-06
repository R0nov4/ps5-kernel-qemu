#!/usr/bin/env python3
"""WP1 item 1 — Sony HV hypercall ABI: the 33 wrappers + FULL xref map.

Outputs:
  download/ps5_wp1/wp1_1_hypercalls.json   (machine-readable, full detail)
  download/ps5_wp1/wp1_1_hypercalls.txt    (human audit trail)
Method (no guessing):
  A) split wrapper region 0xffffffff9f006a10..0x9f00720d into functions by linear disasm
     (function ends at ret/jmp/ud2; skip 0x90/0xCC padding);
  B) per wrapper: hypercall number from EAX dataflow, arg marshalling from register writes;
  C) xrefs: (1) E8/E9 rel32 whole-text scan targeting wrapper region,
            (2) absolute qword pointers in DATA -> wrapper region,
            (3) absolute qword pointers in TEXT -> wrapper region,
            (4) lea rip-relative in TEXT -> wrapper region;
     every E8/E9/lea hit is back-sweep verified (aligned instruction, back>=1);
  D) for every caller: containing function (global call-target map), all strings it
     references (RIP-relative), and data-side names adjacent to pointers to it.
"""
import sys, os, json, struct, re
sys.path.insert(0, "./scripts")
import wp1_lib as L
import numpy as np
from collections import defaultdict

OUT_DIR = "./download/ps5_wp1"
os.makedirs(OUT_DIR, exist_ok=True)
REP = []            # audit-trail lines
def P(s=""):
    print(s)
    REP.append(s)

W0 = 0xFFFFFFFF9F006A10
W1 = 0xFFFFFFFF9F00720D
WEND = W1 + 0x200    # scan past: last wrappers + their tails

ARGREGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")

# ============================================================
# A) split the wrapper region into functions
# ============================================================
P("=" * 100)
P("A) WRAPPER REGION FUNCTION SPLIT  0xffffffff9f006a10 .. 0xffffffff9f00720d")
P("=" * 100)

# context: what precedes W0? (make sure W0 is really the first wrapper)
P("\n-- look-behind: 0x9f0069e0..0x9f006a10 --")
P(L.disasm_str(0xFFFFFFFF9F0069E0, 0x30, maxins=24))

funcs = []          # {start, end, insns, vmmcalls:[va], tail_jmp}
cur_start = W0
insns = []
pos = W0
vmm_sites = []
tail_jmp = None

def _flush(end_pos):
    global funcs, insns, vmm_sites, tail_jmp
    if insns:
        funcs.append({"start": cur_start, "end": end_pos, "insns": list(insns),
                      "vmmcalls": list(vmm_sites), "tail_jmp": tail_jmp})
    del insns[:]
    del vmm_sites[:]
    tail_jmp = None

while pos < WEND:
    lst = L.disasm(pos, 0x40, maxins=8)
    if not lst:
        off = L.va2off(pos)
        b = L.text[off]
        if b in (0x90, 0xCC):
            pos += 1
            continue
        P(f"!! undecodable at 0x{pos:x}: {L.read(pos,8).hex()}")
        break
    ins = lst[0]
    insns.append(ins)
    if ins.mnemonic == "vmmcall":
        vmm_sites.append(ins.address)
    pos += ins.size
    ended = False
    if ins.mnemonic in ("ret", "ud2"):
        ended = True
    elif ins.mnemonic == "jmp":
        m = re.match(r"^0x[0-9a-f]+$", ins.op_str.strip())
        if m:
            t = int(ins.op_str, 16)
            if not (cur_start <= t < pos):     # jump target outside = tail-call
                tail_jmp = t
                ended = True
        else:
            ended = True                       # indirect jmp ends function
    if ended:
        _flush(pos)
        while pos < WEND and L.text[L.va2off(pos)] in (0x90, 0xCC):
            pos += 1
        cur_start = pos
_flush(pos)   # last partial function

total_vmm = sum(len(f["vmmcalls"]) for f in funcs)
wrappers = [f for f in funcs if f["vmmcalls"]]
P(f"\nsplit into {len(funcs)} functions, {total_vmm} vmmcall sites; {len(wrappers)} wrappers")

# cross-check vs global vmmcall scan.
# Back-sweep alignment alone can "verify" byte patterns sitting INSIDE other
# instructions (desynchronized streams land on them). The earlier session's
# manual context review adjudicated 4 such false positives; re-prove one here
# and adopt the adjudication as ground truth.
P("\n-- false-positive proof: context around 0x9e6ab6c9 (real stream = FPU code) --")
P(L.disasm_str(0xFFFFFFFF9E6AB6B8, 0x40, maxins=14, mark_va=0xFFFFFFFF9E6AB6C9))
hits, i = [], L.text.find(b"\x0f\x01\xd9")
while i != -1:
    hits.append(i)
    i = L.text.find(b"\x0f\x01\xd9", i + 1)
KNOWN_FALSE = {0xFFFFFFFF9E6AB6C9, 0xFFFFFFFF9E6AB7BE, 0xFFFFFFFF9E6AB8A3,
               0xFFFFFFFF9ED157FD}
real_global = [L.TEXT_BASE + h for h in hits if (L.TEXT_BASE + h) not in KNOWN_FALSE]
P(f"global scan: raw={len(hits)}, true after adjudication={len(real_global)}")
outside = [hex(v) for v in real_global if not (W0 <= v <= W1 + 0x30)]
P(f"true vmmcall sites OUTSIDE wrapper region: {outside if outside else 'NONE (all inside)'}")

# ============================================================
# B) per-wrapper: hypercall number + arg marshalling
# ============================================================
P("\n" + "=" * 100)
P("B) PER-WRAPPER ABI (EAX number + argument marshalling)")
P("=" * 100)

def eax_value_and_marshalling(f):
    """Track EAX + arg-register writes across the WHOLE function; record the
    EAX state at each vmmcall site (multi-vmmcall functions supported)."""
    sites = []                 # per vmmcall: eax state at that point
    eax = {"kind": "unknown", "val": None, "src": None}
    writes = []                # arg-reg writes (with site index)
    n_emitted = 0
    for ins in f["insns"]:
        if ins.mnemonic == "vmmcall":
            sites.append(dict(eax))
            n_emitted += 1
            continue
        m = ins.mnemonic
        o = ins.op_str
        if m == "mov" and o.startswith("eax, ") and "," in o:
            src = o.split(", ", 1)[1]
            if src.startswith("0x") or src.lstrip("-").isdigit():
                eax = {"kind": "const", "val": int(src, 0) & 0xFFFFFFFF}
            else:
                eax = {"kind": "dynamic", "src": src}
        elif m == "xor" and o.replace(" ", "") == "eax,eax":
            eax = {"kind": "const", "val": 0}
        elif m == "lea" and o.startswith("eax, "):
            eax = {"kind": "lea", "src": o.split(", ", 1)[1]}
        for r in ("rdi", "rsi", "rdx", "rcx", "r8", "r9", "ebx", "edi", "esi", "edx", "ecx"):
            if (m in ("mov", "lea", "movzx", "movsx", "xor")) and o.startswith(r + ", "):
                writes.append(f"{m} {o}")
                break
    if not sites:
        sites = [eax]
    return sites, writes

wrapper_records = []
for f in wrappers:
    eax_sites, writes = eax_value_and_marshalling(f)
    dis = []
    for ins in f["insns"]:
        tag = " <<< VMMCALL" if ins.mnemonic == "vmmcall" else ""
        dis.append(f"   0x{ins.address:x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}{tag}")
    rec = {
        "start": f["start"], "end": f["end"], "size": f["end"] - f["start"],
        "n_vmmcall": len(f["vmmcalls"]), "eax_at_vmmcall": eax_sites,
        "tail_jmp": f["tail_jmp"],
        "arg_writes": writes, "disasm": "\n".join(dis),
    }
    wrapper_records.append(rec)
    tail = f"  tail-jmp->0x{f['tail_jmp']:x}" if f["tail_jmp"] else ""
    P(f"\nwrapper 0x{f['start']:x}..0x{f['end']:x} ({f['end']-f['start']:3d} B)  "
      f"vmmcall x{len(f['vmmcalls'])}  EAX@sites={eax_sites}{tail}")
    if writes:
        P("   arg-register writes in wrapper:")
        for w in writes:
            P(f"     {w}")
    P("\n".join(dis))

# also list non-wrapper functions interleaved in region (context)
nonwrap = [f for f in funcs if not f["vmmcalls"]]
P(f"\nnon-vmmcall functions inside region: {[(hex(f['start']), hex(f['end'])) for f in nonwrap]}")

# ============================================================
# C) XREFS
# ============================================================
P("\n" + "=" * 100)
P("C) XREF SCAN (E8/E9 rel32 + DATA qword ptrs + TEXT qword ptrs + lea rip)")
P("=" * 100)

wrapper_starts = set(r["start"] for r in wrapper_records)
region_lo, region_hi = W0, W1 + 0x30

# --- C1: E8/E9 rel32 ---
xrefs = defaultdict(list)     # wrapper start -> [ {site, kind, target, verified} ]
call_scan = []
for opcode, kind in ((0xE8, "call"), (0xE9, "jmp")):
    i = 0
    while True:
        i = L.text.find(bytes([opcode]), i)
        if i == -1 or i + 5 > L.TEXT_SIZE:
            break
        site = L.TEXT_BASE + i
        rel = struct.unpack_from("<i", L.text, i + 1)[0]
        tgt = site + 5 + rel
        if region_lo <= tgt <= region_hi:
            ok, back = L.aligned_reachable(site, maxback=48, maxins=64)
            lst = L.disasm(site, 8, maxins=1)
            good = ok and lst and lst[0].mnemonic == kind
            call_scan.append({"site": site, "kind": kind, "target": tgt,
                              "verified": bool(good)})
        i += 1
verified_calls = [c for c in call_scan if c["verified"]]
suspicious = [c for c in call_scan if not c["verified"]]
P(f"\nC1 E8/E9 targeting wrapper region: {len(call_scan)} raw, {len(verified_calls)} verified, "
  f"{len(suspicious)} rejected")
for c in suspicious:
    P(f"   REJECT 0x{c['site']:x} {c['kind']} -> 0x{c['target']:x}")

# --- C2: absolute pointers in DATA ---
arr = np.frombuffer(L.data, dtype="<u8")
m2 = (arr >= region_lo) & (arr <= region_hi)
idx2 = np.nonzero(m2)[0]
data_ptr_xrefs = []
for k in idx2:
    off = int(k)
    val = int(arr[k])
    data_ptr_xrefs.append({"at": L.DATA_BASE + off * 8, "value": val})
P(f"C2 DATA qword pointers into wrapper region: {len(data_ptr_xrefs)}")
for d in data_ptr_xrefs:
    tag = "wrapper-start" if d["value"] in wrapper_starts else "mid-function"
    P(f"   @data 0x{d['at']:x} -> 0x{d['value']:x} ({tag})")

# --- C3: absolute pointers in TEXT (aligned + unaligned byte-find) ---
text_ptr_xrefs = []
tarr = np.frombuffer(L.text[: L.TEXT_SIZE - (L.TEXT_SIZE % 8)], dtype="<u8")
m3 = (tarr >= region_lo) & (tarr <= region_hi)
for k in np.nonzero(m3)[0]:
    text_ptr_xrefs.append({"at": L.TEXT_BASE + int(k) * 8, "value": int(tarr[k]),
                           "aligned": True})
for va in sorted(wrapper_starts):
    pat = struct.pack("<Q", va)
    i = L.text.find(pat)
    while i != -1:
        if i % 8 != 0:
            text_ptr_xrefs.append({"at": L.TEXT_BASE + i, "value": va, "aligned": False})
        i = L.text.find(pat, i + 1)
P(f"C3 TEXT absolute qwords into wrapper region: {len(text_ptr_xrefs)}")
for d in text_ptr_xrefs:
    P(f"   @text 0x{d['at']:x} -> 0x{d['value']:x} ({'aligned' if d['aligned'] else 'unaligned'})")

# --- C4: lea rip-relative into wrapper region ---
lea_xrefs = []
i = 0
MODRMS = {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}
while True:
    i = L.text.find(b"\x8d", i)
    if i == -1 or i + 6 > L.TEXT_SIZE:
        break
    if i >= 1 and 0x48 <= L.text[i - 1] <= 0x4F and L.text[i + 1] in MODRMS:
        site = L.TEXT_BASE + i - 1
        disp = struct.unpack_from("<i", L.text, i + 2)[0]
        tgt = site + 7 + disp
        if region_lo <= tgt <= region_hi:
            ok, _ = L.aligned_reachable(site, maxback=48, maxins=64)
            lst = L.disasm(site, 8, maxins=1)
            if ok and lst and lst[0].mnemonic == "lea":
                lea_xrefs.append({"site": site, "target": tgt})
    i += 1
P(f"C4 lea rip-relative into wrapper region (verified): {len(lea_xrefs)}")
for d in lea_xrefs:
    P(f"   @text 0x{d['site']:x} lea -> 0x{d['target']:x}")

# ============================================================
# D) caller analysis: containing function, strings, data-side names
# ============================================================
P("\n" + "=" * 100)
P("D) CALLER SEMANTICS (strings referenced by each caller + data-side names)")
P("=" * 100)

def site_to_wrapper(tgt):
    best = None
    for r in wrapper_records:
        if r["start"] <= tgt < r["end"]:
            best = r
            break
    return best

all_xrefs = []
for c in verified_calls:
    r = site_to_wrapper(c["target"])
    if r:
        all_xrefs.append({"wrapper": r["start"], "kind": c["kind"], "site": c["site"]})
for d in data_ptr_xrefs:
    r = site_to_wrapper(d["value"])
    if r:
        all_xrefs.append({"wrapper": r["start"], "kind": "data-ptr", "site": d["at"]})
for d in text_ptr_xrefs:
    r = site_to_wrapper(d["value"])
    if r:
        all_xrefs.append({"wrapper": r["start"], "kind": "text-ptr", "site": d["at"]})
for d in lea_xrefs:
    r = site_to_wrapper(d["target"])
    if r:
        all_xrefs.append({"wrapper": r["start"], "kind": "lea", "site": d["site"]})

callers = {}
for x in all_xrefs:
    w = x["wrapper"]
    if x["kind"] in ("call", "jmp"):
        fstart, fend = L.containing_function(x["site"])
    else:
        fstart, fend = x["site"], None     # ptr/lea: the containing code, if in text
        if L.in_text(x["site"]):
            fstart, fend = L.containing_function(x["site"])
    if fstart is None:
        continue
    key = (w, fstart)
    callers.setdefault(key, {"kinds": set(), "sites": []})
    callers[key]["kinds"].add(x["kind"])
    callers[key]["sites"].append(x["site"])

P(f"\ndistinct (wrapper, caller-function) pairs: {len(callers)}")

caller_details = []
in_region_callers = []
for (w, fstart), info in sorted(callers.items(), key=lambda kv: (kv[0][0], kv[0][1])):
    fend = L.containing_function(fstart)[1] or fstart + 0x200
    if not L.in_text(fstart):
        continue
    if W0 <= fstart < WEND:
        in_region_callers.append((hex(w), hex(fstart), sorted(info["kinds"])))
        continue          # wrapper-to-wrapper thunk: not a kernel caller
    strings = L.function_strings(fstart, fend)
    # buckets
    files = sorted(set(s for _, _, s in strings if "/" in s and (".c" in s or ".h" in s)))
    fmts = sorted(set(s for _, _, s in strings if "%" in s))
    idents = sorted(set(s for _, _, s in strings if L.looks_like_name(s) and "/" not in s and "%" not in s))
    # data-side names for this function
    dptrs = L.data_ptrs_to(fstart)
    names = []
    for dp in dptrs[:16]:
        for k, s, v in L.nearby_name_strings(dp, span=4):
            names.append((hex(dp), k, s))
    rec = {"wrapper": w, "caller_func": fstart, "caller_end": fend,
           "size": fend - fstart, "kinds": sorted(info["kinds"]),
           "sites": [hex(s) for s in info["sites"]],
           "file_strings": files, "format_strings": fmts[:24], "name_strings": idents[:24],
           "n_strings_total": len(strings),
           "data_ptrs_to_caller": [hex(d) for d in dptrs[:16]],
           "data_side_names": names[:12]}
    caller_details.append(rec)
    P(f"\n--- caller of wrapper 0x{w:x}: func 0x{fstart:x}..0x{fend:x} "
      f"({fend-fstart} B) kinds={rec['kinds']} sites={rec['sites']}")
    if files:
        P(f"    FILE PATHS: {files}")
    if fmts:
        P(f"    FORMAT/panic strings: {fmts[:12]}")
    if idents:
        P(f"    identifier-like: {idents[:16]}")
    if names:
        P(f"    data-side names: {names[:8]}")

P(f"\nwrapper-to-wrapper thunks (in-region, NOT kernel callers): {len(in_region_callers)}")
for w, f, k in in_region_callers:
    P(f"   thunk func {f} -> wrapper {w} via {k}")
P(f"real kernel callers (out-of-region, string-analyzed): {len(caller_details)}")

# ============================================================
# save
# ============================================================
out = {
    "region": {"lo": hex(W0), "hi": hex(W1), "scan_end": hex(WEND)},
    "wrappers": [{"start": hex(r["start"]), "end": hex(r["end"]), "size": r["size"],
                   "n_vmmcall": r["n_vmmcall"],
                   "eax_at_vmmcall": r["eax_at_vmmcall"],
                   "tail_jmp": hex(r["tail_jmp"]) if r["tail_jmp"] else None,
                   "arg_writes": r["arg_writes"], "disasm": r["disasm"]}
                  for r in wrapper_records],
    "non_wrapper_functions_in_region": [{"start": hex(f["start"]), "end": hex(f["end"])}
                                        for f in nonwrap],
    "xrefs_call_jmp": [{"site": hex(c["site"]), "kind": c["kind"],
                        "target": hex(c["target"])} for c in verified_calls],
    "xrefs_data_ptrs": [{"at": hex(d["at"]), "value": hex(d["value"])} for d in data_ptr_xrefs],
    "xrefs_text_ptrs": [{"at": hex(d["at"]), "value": hex(d["value"])} for d in text_ptr_xrefs],
    "xrefs_lea": [{"site": hex(d["site"]), "target": hex(d["target"])} for d in lea_xrefs],
    "callers": [{k: v for k, v in c.items()} for c in caller_details],
}
json.dump(out, open(f"{OUT_DIR}/wp1_1_hypercalls.json", "w"), indent=1)
open(f"{OUT_DIR}/wp1_1_hypercalls.txt", "w").write("\n".join(REP))
P(f"\nsaved -> {OUT_DIR}/wp1_1_hypercalls.json / .txt")
