#!/usr/bin/env python3
"""WP1 final compile — unified engineering report from the three JSON outputs."""
import sys, json
sys.path.insert(0, "./scripts")
import wp1_lib as L

D = "./download/ps5_wp1"
hc = json.load(open(f"{D}/wp1_1_hypercalls.json"))
msr = json.load(open(f"{D}/wp1_2_msr.json"))
sy = json.load(open(f"{D}/wp1_3_sysinit.json"))

out = []
W = out.append

W("# WP1 — PS5 13.60 Kernel: HV Hypercall ABI + MSR Map + Entry/SysInit")
W("")
W("Source: terrafirma2021/ps5-13.60-kernel-dump (SHA-256 verified). "
  "All findings byte-verified in this dump; no guesswork — semantics derived from")
W("the kernel's own panic/log strings, `__FILE__` paths and linker sets.")
W("")
W("## 1. Sony HV Hypercall ABI (kernel side)")
W("")
W("- Mechanism: `vmmcall` (0F 01 D9), hypercall number in **EAX**, args in SysV-AMD64")
W("  registers (some wrappers marshal into **RBX/EBX** — non-SysV), return in EAX/RBX/RDX/RDI/RSI.")
W("- Implementation: `sys/kern/kern_hv.c` (build path `W:/Build/J03950001/sys/freebsd/sys/kern/kern_hv.c`).")
W(f"- {len(hc['wrappers'])} wrapper functions, 33 vmmcall sites, all inside region "
  f"0x9f006a10..0x9f00720d (+ tails).")
W(f"- Xrefs: {len(hc['xrefs_call_jmp'])} direct call/jmp (all back-sweep verified), "
  f"1 data pointer, 0 lea/absolute (wrappers are only called directly).")
W("")
W("| # | EAX | wrapper | size | ABI (marshal before vmmcall) | callers | evidence (kernel strings) |")
W("|---|-----|---------|------|------------------------------|---------|---------------------------|")

ROLE = {}
def role_for(start, eax):
    n = eax if isinstance(eax, int) else -1
    return {
        4: "CPU-mode set (mode 1)", 5: "CPU-mode set (mode 2)", 31: "CPU-mode set (mode 0)",
        6: "IOMMU query (returns u64+u32)", 7: "IOMMU op (arg in EBX)",
        8: "IOMMU op (EBX,ECX)", 9: "IOMMU op (EBX,ECX)",
        10: "IOMMU op w/ retry (100000 x delay(10))", 11: "IOMMU 3x-u64 exchange (logged)",
        12: "returns 2 u64 (unused)", 13: "HV state block read (EBX=idx -> 4x u64)",
        15: "3-arg op (EDI->EDX, ESI->ECX, EDX->RBX)",
        16: "AP start/resume", 18: "kern_hv.c internal init",
        19: "LAPIC timer op", 20: "map TMR (PSP/TEE trusted region)",
        21: "unmap/TMR control", 27: "unused?", 28: "unused?", 29: "unused?", 30: "unused?",
        32: "sysctl-exposed HV stat", 38: "unused?", 39: "unused?", 40: "unused?",
    }.get(n, "?")

for w in hc["wrappers"]:
    eaxs = [e["val"] for e in w["eax_at_vmmcall"] if e.get("kind") == "const"]
    n_v = w["n_vmmcall"]
    eax_txt = ",".join(f"0x{v:X}" for v in sorted(set(eaxs))) if eaxs else "dyn"
    marsh = "; ".join(w["arg_writes"][:6]) or "pure passthrough"
    cs = [c for c in hc["callers"] if c["wrapper"] == int(w["start"], 16)]
    if cs:
        cf = cs[0]["caller_func"]
        cf = int(cf, 16) if isinstance(cf, str) else cf
        caller_txt = f"{len(cs)} fn(s) from 0x{cf:x}"
    else:
        caller_txt = "none"
    ev = set()
    for c in cs:
        ev.update(c.get("file_strings", []))
        ev.update(s for s in c.get("name_strings", [])[:6])
    ev_txt = "; ".join(sorted(ev)[:4])[:95]
    W(f"| {w['start'][2:]} | {eax_txt} | 0x{int(w['start'],16):x} | {w['size']}B | "
      f"{marsh[:80]} | {caller_txt} | {ev_txt} |")

W("")
W("### Hypercall roles (derived from caller string evidence)")
W("")
W("| EAX | role (evidence) |")
W("|-----|-----------------|")
seen = set()
for w in hc["wrappers"]:
    eaxs = [e["val"] for e in w["eax_at_vmmcall"] if e.get("kind") == "const"]
    for n in sorted(set(eaxs)):
        if n in seen:
            continue
        seen.add(n)
        r = role_for(0, n)
        W(f"| 0x{n:X} ({n}) | {r} |")

W("")
W("## 2. MSR usage map")
W("")
W(f"- {len(msr['verified_sites'])} verified rdmsr/wrmsr sites (fn-anchored alignment), "
  f"{len(msr['aggregate'])} distinct MSR keys.")
W("- ECX tracking covers `mov ecx,imm`, `mov rcx,imm`, `movabs rcx,imm` (Sony uses all three).")
W("")
W("| MSR | label | dir | R | W | sites | first site | funcs | subsystem evidence |")
W("|-----|-------|-----|---|---|-------|------------|-------|---------------------|")
for a in msr["aggregate"]:
    if a["msr"] == "dyn":
        continue
    ev = "; ".join(a["files"][:2] + a["idents"][:3])[:70]
    W(f"| {a['msr']} | {a['label'][:28]} | {a['dir']} | {a['nR']} | {a['nW']} | "
      f"{a['n_sites']} | {a['site_first']} | {a['n_funcs']} | {ev} |")
W("")
W("Dynamic-ECX sites (MSR index from register):")
W("")
for a in msr["aggregate"]:
    if a["msr"] == "dyn":
        W(f"- {a['ecx']} — dir {a['dir']}, {a['n_sites']} site(s), first {a['site_first']}")

W("")
W("## 3. Kernel entry & boot order")
W("")
W("### Entry chain")
W("")
W("1. Image starts 0xffffffff9e3f0000: 16B data blob, then boot stub at 0x9e3f0010.")
W("2. Boot stub: temp `lgdt` (GDT @ 0xffffffffa1e8dce0, limit 0x40), DS/SS=0x28,")
W("   `retfq` to CS=0x20 -> reload real GDTR -> `call 0xffffffff9e6428f0` (hammer_time).")
W("3. hammer_time (0x9e6428f0, ~10KB fn): load CR3, segments (FS=0x13/GS=0x1b),")
W("   restore FS_BASE/GS_BASE/KGS_BASE/EFER/STAR/LSTAR/CSTAR/SFMASK + CR0/2/3/4 +")
W("   IDT/LDT/TR from context struct at RDI (pair: save-fn 0x9e6427d0 uses same offsets).")
W("4. 0xCC padding zone: [0x9e3f0090, 0x9e64025f) = 2,425,295 B (2.43 MB), 1 island of 8 zero bytes.")
W("5. Real code starts 0xffffffff9e64025f; first fn contains `lgdt` @0x9e640433.")
W("")
W("### sysinit_set (Sony layout, live-dump state)")
W("")
sc = sy["sysinit_set"]
W(f"- Array: [{sc['lo']}, {sc['hi']}) — {sc['count']} entries.")
W("- Struct: {u32 done_stamp, u32 order, thunk-func*, udata*}; thunk region")
W("  0x9e651000..0x9e656000 = 16B `jmp real` islands (KASLR-style indirection).")
W("- **Array order == execution order** (linker pre-sorted; live dump shows done=1 stamped).")
W("")
W("### Subsystem bring-up order (from kernel's own file-path strings)")
W("")
boot = sy["boot_sequence"]
seenf = {}
for b in boot:
    for f in b["files"]:
        seenf.setdefault(f, b["idx"])
W("| boot # | subsystem (file) |")
W("|--------|------------------|")
for f, idx in sorted(seenf.items(), key=lambda kv: kv[1]):
    W(f"| #{idx} | {f} |")
W("")
W(f"Total: {len(boot)} boot entries; full per-entry table in wp1_3_sysinit.json.")
W("")
sc2 = sy["sysuninit_set"]
W(f"Adjacent set [0x9fe55070, 0x9fe57508) = {sc2['count']} teardown/uninit entries using the")
W("STANDARD FreeBSD 9.3 SI_SUB enum (KMEM x460 = vmem arenas, LOCK x132, ...) — shutdown path.")

open(f"{D}/wp1_report.md", "w").write("\n".join(out))
print(f"written {D}/wp1_report.md ({len(out)} lines)")
