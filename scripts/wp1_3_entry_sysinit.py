#!/usr/bin/env python3
"""WP1 item 3 — real kernel entry point (after the 0xCC padding) + SYSINIT table.

PART A (entry):
  - exact map of the 0xCC padding zone (start, end, islands of non-CC bytes)
  - head boot code at 0xffffffff9e3f0000 (GDT loader -> hammer_time call)
  - hammer_time (0xffffffff9e6428f0) identification: context-restore prologue
  - all lgdt/lidt/sgdt/sidt sites in text (verified)
PART B (sysinit):
  - FreeBSD 9.3 layout: struct sysinit { u32 subsystem; u32 order; func ptr; udata ptr }
    (24 bytes), sysinit_set = contiguous array of pointers to such structs
  - strict scan: sub must match a FreeBSD 9.3 SI_SUB enum value (or be reported
    as Sony-added), order must match SI_ORDER family, func must point into text
  - find the longest contiguous pointer run -> set_sysinit_set bounds
  - extract, sort by (sub, order) => EXACT subsystem bring-up order
Outputs: download/ps5_wp1/wp1_3_entry_sysinit.json / .txt
"""
import sys, os, json, struct
sys.path.insert(0, "./scripts")
import wp1_lib as L
import numpy as np
from collections import Counter, defaultdict

OUT_DIR = "./download/ps5_wp1"
os.makedirs(OUT_DIR, exist_ok=True)
REP = []
def P(s=""):
    print(s)
    REP.append(s)

# FreeBSD 9.3 sys/sys/kernel.h (reference; Sony may add values)
SI_SUB = {
    0x0000000: "SI_SUB_DUMMY", 0x0000001: "SI_SUB_DONE", 0x0700000: "SI_SUB_TUNABLES",
    0x0800001: "SI_SUB_COPYRIGHT", 0x0880000: "SI_SUB_SETTINGS",
    0x0900000: "SI_SUB_MTX_POOL_STATIC", 0x0980000: "SI_SUB_LOCKMGR",
    0x1000000: "SI_SUB_VM", 0x1800000: "SI_SUB_KMEM", 0x1A00000: "SI_SUB_KVM_RSRC",
    0x1A80000: "SI_SUB_WITNESS", 0x1AC0000: "SI_SUB_MTX_POOL_DYNAMIC",
    0x1B00000: "SI_SUB_LOCK", 0x1C00000: "SI_SUB_EVENTHANDLER",
    0x1E00000: "SI_SUB_VNET_PRELINK", 0x2000000: "SI_SUB_KLD", 0x2100000: "SI_SUB_CPU",
    0x2110000: "SI_SUB_RACCT", 0x2120000: "SI_SUB_RANDOM", 0x2140000: "SI_SUB_KDTRACE",
    0x2180000: "SI_SUB_MAC", 0x21C0000: "SI_SUB_MAC_POLICY", 0x21D0000: "SI_SUB_MAC_LATE",
    0x21E0000: "SI_SUB_VNET", 0x2200000: "SI_SUB_INTRINSIC", 0x2300000: "SI_SUB_VM_CONF",
    0x2380000: "SI_SUB_DDB_SERVICES", 0x2400000: "SI_SUB_RUN_QUEUE",
    0x2480000: "SI_SUB_KTRACE", 0x2490000: "SI_SUB_OPENSOLARIS",
    0x24A0000: "SI_SUB_CYCLIC", 0x24C0000: "SI_SUB_AUDIT",
    0x2500000: "SI_SUB_CREATE_INIT", 0x2600000: "SI_SUB_SCHED_IDLE",
    0x2700000: "SI_SUB_MBUF", 0x2800000: "SI_SUB_INTR", 0x2800001: "SI_SUB_SOFTINTR",
    0x2900000: "SI_SUB_ACL", 0x2F00000: "SI_SUB_DEVFS", 0x3000000: "SI_SUB_INIT_IF",
    0x3010000: "SI_SUB_NETGRAPH", 0x3020000: "SI_SUB_DTRACE",
    0x3048000: "SI_SUB_DTRACE_PROVIDER", 0x308C000: "SI_SUB_DTRACE_ANON",
    0x3100000: "SI_SUB_DRIVERS", 0x3800000: "SI_SUB_CONFIGURE", 0x4000000: "SI_SUB_VFS",
    0x4800000: "SI_SUB_CLOCKS", 0x5800000: "SI_SUB_CLIST", 0x6400000: "SI_SUB_SYSV_SHM",
    0x6800000: "SI_SUB_SYSV_SEM", 0x6C00000: "SI_SUB_SYSV_MSG", 0x6E00000: "SI_SUB_P1003_1B",
    0x7000000: "SI_SUB_PSEUDO", 0x7400000: "SI_SUB_EXEC", 0x8000000: "SI_SUB_PROTO_BEGIN",
    0x8400000: "SI_SUB_PROTO_IF", 0x8600000: "SI_SUB_PROTO_DOMAININIT",
    0x8800000: "SI_SUB_PROTO_DOMAIN", 0x8800001: "SI_SUB_PROTO_IFATTACHDOMAIN",
    0x8FFFFFF: "SI_SUB_PROTO_END", 0x9000000: "SI_SUB_KPROF",
    0xA000000: "SI_SUB_KICK_SCHEDULER", 0xA800000: "SI_SUB_INT_CONFIG_HOOKS",
    0xB000000: "SI_SUB_ROOT_CONF", 0xB200000: "SI_SUB_DUMP_CONF",
    0xB380000: "SI_SUB_RAID", 0xC000000: "SI_SUB_SWAP", 0xD000000: "SI_SUB_INTRINSIC_POST",
    0xD800000: "SI_SUB_SYSCALLS", 0xDC00000: "SI_SUB_VNET_DONE",
    0xE000000: "SI_SUB_KTHREAD_INIT", 0xE400000: "SI_SUB_KTHREAD_PAGE",
    0xE800000: "SI_SUB_KTHREAD_VM", 0xEA00000: "SI_SUB_KTHREAD_BUF",
    0xEC00000: "SI_SUB_KTHREAD_UPDATE", 0xEE00000: "SI_SUB_KTHREAD_IDLE",
    0xF000000: "SI_SUB_SMP", 0xF100000: "SI_SUB_RACCTD", 0xFFFFFFF: "SI_SUB_LAST",
}
SI_ORDER = {0x0: "FIRST", 0x1: "SECOND", 0x2: "THIRD", 0x3: "FOURTH",
            0x1000000: "MIDDLE", 0xFFFFFFF: "ANY/LAST"}

# ======================================================================
# PART A: entry point
# ======================================================================
P("=" * 100)
P("A) KERNEL ENTRY ANALYSIS")
P("=" * 100)

head16 = L.read(L.TEXT_BASE, 16)
P(f"\nfirst 16 bytes of image @0xffffffff9e3f0000: {head16.hex(' ')}")
P("  -> 16-byte data blob (call-displacement + zeros) preceding the boot function")

P("\n-- A1. boot stub (0xffffffff9e3f0010, GDT loader) full disasm --")
P(L.disasm_str(0xFFFFFFFF9E3F0010, 0x80, maxins=60))

P("\n-- A2. hammer_time candidate 0xffffffff9e6428f0 (context restore) --")
fs, fe = L.containing_function(0xFFFFFFFF9E6428F0)
P(f"containing-function bounds: 0x{fs:x}..0x{fe:x} ({fe-fs} B)")
P(L.disasm_str(0xFFFFFFFF9E6428F0, 0xC0, maxins=48))
P("\nhammer_time tail check (search for mi_startup-style loop markers):")
P(L.disasm_str(0xFFFFFFFF9E647920, 0x60, maxins=24))

P("\n-- A3. who references the boot stub / blob? --")
for tgt in (0xFFFFFFFF9E3F0000, 0xFFFFFFFF9E3F0010, 0xFFFFFFFF9E3F0051):
    dp = L.data_ptrs_to(tgt)
    calls = []
    i = 0
    while True:
        i = L.text.find(b"\xe8", i)
        if i == -1 or i + 5 > L.TEXT_SIZE:
            break
        rel = struct.unpack_from("<i", L.text, i + 1)[0]
        t = L.TEXT_BASE + i + 5 + rel
        if t == tgt:
            calls.append(L.TEXT_BASE + i)
        i += 1
    P(f"  0x{tgt:x}: data-ptrs={[hex(x) for x in dp]}, direct-calls={[hex(x) for x in calls]}")
P("  0xffffffff9e8e5d70 (called by the first 5 bytes if entry=0x9e3f0000):")
P(L.disasm_str(0xFFFFFFFF9E8E5D70, 0x40, maxins=14))

P("\n-- A4. descriptor-table instruction sites (lgdt/lidt/sgdt/sidt) --")
DESK = {0: "sgdt", 1: "sidt", 2: "lgdt", 3: "lidt"}
i = 0
desc_sites = []
while True:
    i = L.text.find(b"\x0f\x01", i)
    if i == -1 or i + 3 > L.TEXT_SIZE:
        break
    modrm = L.text[i + 2]
    reg = (modrm >> 3) & 7
    if reg in DESK and (modrm >> 6) != 3:
        va = L.TEXT_BASE + i
        ok, _ = L.aligned_reachable(va, maxback=48, maxins=64)
        lst = L.disasm(va, 8, maxins=1)
        if ok and lst and lst[0].mnemonic == DESK[reg]:
            fstart, _ = L.containing_function(va)
            desc_sites.append({"va": va, "op": DESK[reg], "func": fstart})
    i += 1
for d in desc_sites:
    f = d['func']
    where = ("   <<< BOOT STUB" if d['va'] < 0xFFFFFFFF9E400000 else
             "   <<< hammer_time" if f == 0xFFFFFFFF9E6428F0 else
             f"   (func 0x{f:x})" if f else "   (before CODE_BASE / no call-target)")
    P(f"  {d['op']:4s} @0x{d['va']:x}{where}")
P(f"total descriptor-table sites: {len(desc_sites)} "
  f"({Counter(d['op'] for d in desc_sites)})")

P("\n-- A5. 0xCC padding zone map --")
first_cc = 0x90
P(f"boot stub ends at file 0x{0x90:x} (VA 0xffffffff9e3f0090); 0xCC run starts there")
# real code start: first offset >= CODE_BASE-off where 16 consecutive non-CC
off = L.va2off(L.CODE_BASE)
while off < L.TEXT_SIZE and L.text[off] == 0xCC:
    off += 1
real_start = L.off2va(off)
P(f"first non-0xCC byte at/after CODE_BASE: VA 0x{real_start:x} (file 0x{off:x})")
pad_bytes = off - 0x90
P(f"padding zone = [0xffffffff9e3f0090, 0x{real_start:x}) = {pad_bytes:,} bytes "
  f"({pad_bytes/1e6:.2f} MB decimal)")
# islands: non-CC runs >= 8 bytes inside the padding zone
P("\nislands (non-CC runs >= 8B) inside the padding:")
islands = []
p = 0x90
while p < off:
    if L.text[p] != 0xCC:
        q = p
        while q < off and L.text[q] != 0xCC:
            q += 1
        if q - p >= 8:
            islands.append((p, q))
        p = q
    else:
        p += 1
for (a, b) in islands:
    va_a = L.off2va(a)
    blob = L.text[a:min(b, a + 32)]
    P(f"  island 0x{va_a:x}..0x{L.off2va(b):x} ({b-a} B): {blob[:24].hex(' ')}")
    s = L.cstr(va_a, 64)
    if s:
        P(f"     string: {s!r}")
P(f"total islands: {len(islands)}")

# ======================================================================
# PART B: sysinit  — FINAL (v3), all identified empirically:
#   set B..F merged = sysinit_set [0xffffffff9fe51fb0, 0xffffffff9fe55068):
#       1559 entries, struct = {u32 done_stamp(0/1), u32 order, thunk*, udata*}
#       ARRAY ORDER == EXECUTION ORDER (linker pre-sorted; mi_startup runs in
#       sequence and stamps done=1 — this dump is live, hence 1 x ~1531)
#   set G = sysuninit_set [0xffffffff9fe55070, 0xffffffff9fe57508):
#       1171 entries, struct = {u32 SI_SUB (FreeBSD 9.3 enum), u32 SI_ORDER,
#       thunk*, udata*} — shutdown order = reverse (sub desc, order desc)
#   thunk region 0xffffffff9e651000..0xffffffff9e656000: 16B slots `jmp real`
#   (kernel-side PLT/KASLR islands; int3-padded)
# ======================================================================
P("\n" + "=" * 100)
P("B) SYSINIT — boot-sequence table (order = array order) + sysuninit")
P("=" * 100)

arr = np.frombuffer(L.data, dtype="<u8")
n = len(arr)
DATA_B, DATA_E = L.DATA_BASE, L.DATA_END

def thunk_target(va):
    if va is None or va == 0:
        return va
    b = L.read(va, 5)
    if len(b) == 5 and b[0] == 0xE9 and L.in_text(va):
        rel = struct.unpack_from("<i", b, 1)[0]
        return va + 5 + rel
    return va

def set_entries(lo, hi):
    out = []
    for k in range((lo - DATA_B) // 8, (hi - DATA_B) // 8):
        v = int(arr[k])
        if not (DATA_B <= v < DATA_E) or (v - DATA_B) % 8:
            continue
        j = (v - DATA_B) // 8
        if j + 2 >= n:
            continue
        q0, q1, q2 = int(arr[j]), int(arr[j + 1]), int(arr[j + 2])
        f0, f1 = q0 & 0xFFFFFFFF, (q0 >> 32) & 0xFFFFFFFF
        if f0 > 0xFFFFFFF:
            continue
        if not (q1 == 0 or L.in_text(q1)):
            continue
        out.append({"idx": k - (lo - DATA_B) // 8, "struct_va": v,
                    "a": f0, "b": f1, "func": q1, "udata": q2})
    return out

INIT_LO, INIT_HI = 0xFFFFFFFF9FE51FB0, 0xFFFFFFFF9FE55068
UNIN_LO, UNIN_HI = 0xFFFFFFFF9FE55070, 0xFFFFFFFF9FE57508
init_entries = set_entries(INIT_LO, INIT_HI)
unin_entries = set_entries(UNIN_LO, UNIN_HI)
P(f"\nsysinit_set  [0x{INIT_LO:x}, 0x{INIT_HI:x}): {len(init_entries)} entries "
  f"(done-stamp: 1 x{sum(1 for e in init_entries if e['a']==1)}, 0 x{sum(1 for e in init_entries if e['a']==0)})")
P(f"sysuninit_set[0x{UNIN_LO:x}, 0x{UNIN_HI:x}): {len(unin_entries)} entries "
  f"(sub uses FreeBSD 9.3 enum)")

# file-evidence cache per real function
_ev = {}
def ev(func):
    if func in _ev:
        return _ev[func]
    files, fmts, idents = set(), set(), set()
    if func:
        fstart, fend = L.containing_function(func)
        if fstart is not None:
            for _, _, s in L.function_strings(fstart, fend):
                if "/" in s and ".c" in s:
                    files.add(s.replace("W:/Build/J03950001/sys/freebsd/sys/", ""))
                elif "%" in s and len(fmts) < 6:
                    fmts.add(s)
                elif L.looks_like_name(s) and len(idents) < 8:
                    idents.add(s)
    _ev[func] = (sorted(files), sorted(fmts), sorted(idents))
    return _ev[func]

# ---------- boot sequence ----------
P("\n=== BOOT SEQUENCE (sysinit execution order = array order) — first 90 ===")
boot = []
for e in init_entries:
    real = thunk_target(e["func"])
    files, fmts, idents = ev(real)
    uds = L.cstr(e["udata"], 40) if e["udata"] else None
    boot.append({"idx": e["idx"], "order": e["b"], "done": e["a"],
                 "thunk": e["func"], "func": real, "udata": e["udata"],
                 "udata_str": uds, "files": files, "idents": idents})
for b in boot[:90]:
    tag = "DONE" if b["done"] == 1 else "PEND"
    uds = f" [{b['udata_str']}]" if b["udata_str"] else ""
    fl = f"  files={b['files'][:2]}" if b["files"] else ""
    print_line = (f"  #{b['idx']:4d} {tag} ord=0x{b['order']:08X} "
                  f"func=0x{b['func']:x}{uds}{fl}")
    P(print_line)

# aggregate: subsystem stages from file evidence
P("\n=== SUBSYSTEM BRING-UP MAP (grouped by file evidence, in first-appearance order) ===")
seen_files = {}
for b in boot:
    for f in b["files"]:
        if f not in seen_files:
            seen_files[f] = b["idx"]
for f, idx in sorted(seen_files.items(), key=lambda kv: kv[1]):
    P(f"  stage @#{idx:4d}: {f}")

# ---------- sysuninit (shutdown) ----------
P("\n=== SYSUNINIT subsystem histogram (FreeBSD 9.3 SI_SUB enum, from dump) ===")
hist = Counter(e["a"] for e in unin_entries)
for sub in sorted(hist):
    P(f"  0x{sub:08X} {SI_SUB.get(sub, 'SONY-CUSTOM'):28s} x{hist[sub]}")

json.dump({"sysinit_set": {"lo": hex(INIT_LO), "hi": hex(INIT_HI),
                            "count": len(init_entries),
                            "note": "array order == execution order; a=done_stamp"},
           "sysuninit_set": {"lo": hex(UNIN_LO), "hi": hex(UNIN_HI),
                              "count": len(unin_entries)},
           "boot_sequence": [{"idx": b["idx"], "order": hex(b["order"]),
                              "done": b["done"], "thunk": hex(b["thunk"]) if b["thunk"] else 0,
                              "func": hex(b["func"]) if b["func"] else 0,
                              "udata": hex(b["udata"]),
                              "udata_str": b["udata_str"],
                              "files": b["files"], "idents": b["idents"]} for b in boot],
           "sysuninit": [{"sub": e["a"], "sub_name": SI_SUB.get(e["a"], "SONY-CUSTOM"),
                           "order": hex(e["b"]),
                           "func": hex(thunk_target(e["func"]) or 0),
                           "udata": hex(e["udata"]),
                           "udata_str": L.cstr(e["udata"], 40)} for e in unin_entries]},
          open(f"{OUT_DIR}/wp1_3_sysinit.json", "w"), indent=1)
P(f"\nsaved -> {OUT_DIR}/wp1_3_sysinit.json")

open(f"{OUT_DIR}/wp1_3_entry_sysinit.txt", "w").write("\n".join(REP))
P(f"saved -> {OUT_DIR}/wp1_3_entry_sysinit.txt")
