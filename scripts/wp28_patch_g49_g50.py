#!/usr/bin/env python3
"""WP28 — G49 (M_WAITOK livelock guards x26) + G50 (park stub port-0x402)

ROOT CAUSE (user boot6 + GDB @12s, rip=0x9f00a425, rbp chain proves):
  mi_startup -> stage #1296 handler 0x9edf4130 (canvasmap) -> malloc
  0x9eff8b50(size, type, 0x102=M_WAITOK|M_ZERO) at 0x9edf41d9.
  malloc's M_WAITOK top runs the sleep-check 0x9f00a3e0 ('malloc
  (M_WAITOK)' witness) and forwards M_WAITOK into uma_z_alloc —
  the ENOMEM-era wait/retry never satisfies -> the walk thread
  livelocks -> 45s silence, park (0x9e9263a4) never reached.

G49 RECIPE (call-site M_WAITOK->M_NOWOK downgrade, tail-only fns):
  site: e8 (call malloc) -> e9 (jmp slot)          [5B, rsp-neutral]
  slot R1:  and edx,0xfd; call malloc; jmp site+5          [13B]
  slot R2:  and edx,0xfd; call malloc; test rax,rax;
            jz bail; jmp site+5; <retcode>; <epilogue>; ret
  - non-WAITOK flags: bit already clear -> exact no-op
  - WAITOK: allocation still ATTEMPTED (real pointer if memory
    exists); only the un-satisfiable WAIT is removed. NULL then
    either flows on (R1, verified tolerant) or cleanly unwinds
    the caller (R2, WP26/27-proven epilogue replay + 3 gates).
  HARD RULE (the WP27-G48 regression lesson): every guarded fn is
  re-verified NOT reachable from any stage #0..#1295 (early
  closure, 6878 fns) — violation aborts the build.

G50 RECIPE (park stub 0x9E404700): before the printf call, emit
  'WP23: sysinit walk complete; parking.\\n' straight to port
  0x402 with a lodsb/out-dx loop — bypasses the whole kernel
  console stack (run.sh wires isa-debugcon iobase=0x402 ->
  serial.log). Belt-and-suspenders for the park proof.

Slots continue the G46/G47 chain at 0x9E413B80 step 0x80.
Idempotent; ZERO QEMU / ZERO GDB (static capstone + keystone only).
"""
import hashlib, re, struct, sys
from collections import deque
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

SCRIPT_NAME = "wp28_patch_g49_g50.py"
KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"
TEXT_HI = 0x9F780000
SET_LO = 0x9FE51FB0
MALLOC = 0x9EFF8B50
SLOT0, SLOT_STEP = 0x9E413B80, 0x80
EXPECT = "175a002cf7665ff88bb43a04241a6d95"      # user-verified G47-only

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        sys.exit(f"ASM FAILED @ {base:#x}: {code}")
    return bytes(enc)

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704
FINAL_MD5 = "a7f800301bb9571039aff7ab61ce23b8"
h0 = hashlib.md5(bytes(img)).hexdigest()
if h0 == FINAL_MD5:
    print(f"OK {SCRIPT_NAME}: already applied (md5 {FINAL_MD5}) — idempotent exit")
    sys.exit(0)
if h0 != EXPECT:
    print(f"note: base md5 {h0} (expected {EXPECT}; site-byte gates enforce)")

def at(va, n): return bytes(img[va - KTEXT: va - KTEXT + n])
def u64(va): return struct.unpack("<Q", at(va, 8))[0] & 0xFFFFFFFF
def u32(va): return struct.unpack("<I", at(va, 4))[0]

def resolve_entry(f, hops=5):
    seen = set()
    while hops > 0 and f not in seen:
        seen.add(f); b = at(f, 5)
        if b[0:1] == b"\xe9":
            t = f + 5 + struct.unpack("<i", b[1:5])[0]
            if KTEXT <= t < TEXT_HI: f = t; hops -= 1; continue
        break
    return f

def padding_run(va, n=8):
    b = at(va, n)
    return len(b) == n and all(c in (0xCC, 0x90) for c in b)

def prologue_back(va, window=0x1000):
    lo = max(KTEXT, va - window)
    idx = bytes(img).rfind(b"\x55\x48\x89\xe5", lo - KTEXT, va - KTEXT + 1)
    return KTEXT + idx if idx >= 0 else None

def disasm_fn(start, cap=0x2000):
    out = []
    for i in md.disasm(at(start, cap), start):
        out.append(i)
        if padding_run(i.address + i.size, 8): break
    return out

def branch_target(i):
    if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
        try: return int(i.op_str, 16)
        except ValueError: return None
    return None

def parse_prologue(W):
    ins = list(md.disasm(at(W, 48), W))
    if not ins or ins[0].mnemonic != "push" or ins[0].op_str != "rbp": return None
    if len(ins) < 2 or ins[1].mnemonic != "mov" or ins[1].op_str != "rbp, rsp": return None
    pushes, subsum, k = [], 0, 2
    while k < len(ins):
        i = ins[k]
        if i.mnemonic == "push": pushes.append(i.op_str)
        elif i.mnemonic == "sub" and i.op_str.startswith("rsp,"):
            try: subsum += int(i.op_str.split(",")[1].strip(), 0)
            except ValueError: return None
        else: break
        k += 1
    return pushes, subsum

def epilogue_pops(epi):
    pops, addsum, leave = [], 0, False
    for x in epi:
        if x.mnemonic == "pop": pops.append(x.op_str)
        elif x.mnemonic == "add" and x.op_str.startswith("rsp,"):
            addsum += int(x.op_str.split(",")[1].strip(), 0)
        elif x.mnemonic == "leave": leave = True
    return pops, addsum, leave

def prologue_consistent(pushes, subsum, pops, addsum, has_leave):
    popped = [r for r in pops if r != "rbp"]
    if not all(r in pushes for r in popped): return False
    if not ("rbp" in pops or has_leave): return False
    slack = 8 * len([r for r in pushes if r not in pops])
    if has_leave: return not pushes and addsum == subsum == 0
    return addsum == subsum + slack

def rsp_delta(i):
    if i.mnemonic == "push": return -8
    if i.mnemonic == "pop": return 8
    if i.mnemonic == "sub" and i.op_str.startswith("rsp,"):
        return -int(i.op_str.split(",")[1].strip(), 0)
    if i.mnemonic == "add" and i.op_str.startswith("rsp,"):
        return int(i.op_str.split(",")[1].strip(), 0)
    return 0

_cfg_cache = {}
def cfg_states(W, ins):
    if W in _cfg_cache: return _cfg_cache[W]
    byaddr = {i.address: j for j, i in enumerate(ins)}
    def succ(j):
        i = ins[j]
        if i.mnemonic == "jmp":
            if i.op_str.startswith("0x") and int(i.op_str, 16) in byaddr:
                return [byaddr[int(i.op_str, 16)]]
            return []
        if i.mnemonic == "ret": return []
        if i.mnemonic.startswith("j") and i.op_str.startswith("0x"):
            out = []
            t = int(i.op_str, 16)
            if t in byaddr: out.append(byaddr[t])
            if j + 1 < len(ins): out.append(j + 1)
            return out
        return [j + 1] if j + 1 < len(ins) else []
    from collections import deque as _dq
    seen, dq, work = {}, _dq([(0, 8)]), 0
    CAP_WORK, CAP_DELTA = 200000, 0x4000
    while dq and work < CAP_WORK:
        j, d = dq.popleft(); work += 1
        if j >= len(ins) or abs(d) > CAP_DELTA or (j in seen and d in seen[j]): continue
        seen.setdefault(j, set()).add(d)
        if ins[j].mnemonic == "ret": continue
        nd = d + rsp_delta(ins[j])
        for nj in succ(j): dq.append((nj, nd))
    _cfg_cache[W] = (seen, work >= CAP_WORK)
    return _cfg_cache[W]

def find_epilogue(insns):
    best = None
    k = len(insns) - 1
    while k >= 0:
        if insns[k].mnemonic == "ret" and not insns[k].op_str:
            j = k - 1
            while j >= 0 and (insns[j].mnemonic == "pop"
                              or (insns[j].mnemonic == "add" and insns[j].op_str.startswith("rsp,"))
                              or insns[j].mnemonic == "leave"):
                j -= 1
            run = insns[j + 1:k]
            if run and any(x.mnemonic == "leave" or
                           (x.mnemonic == "pop" and x.op_str == "rbp") for x in run):
                best = run
        k -= 1
    return best

# ---- full-text call-site index (for caller voting) ----
call_index = {}
for m in re.finditer(rb"[\xe8\xe9]", img[:TEXT_HI - KTEXT]):
    p = m.start()
    tgt = KTEXT + p + 5 + struct.unpack("<i", img[p+1:p+5])[0]
    if KTEXT <= tgt < TEXT_HI:
        call_index.setdefault(tgt, []).append(KTEXT + p)
rev = {}
for t, sites in call_index.items():
    r = resolve_entry(t) if at(t, 1)[:1] == b"\xe9" else t
    rev.setdefault(r, []).extend(sites)

def vote_return(fn):
    ptr = err = 0
    for site in rev.get(fn, [])[:12]:
        W = prologue_back(site)
        if not W: continue
        ins = disasm_fn(W)
        idx = next((j for j, i in enumerate(ins) if i.address == site), None)
        if idx is None: continue
        for w in ins[idx+1:idx+3]:
            if w.mnemonic == "test" and w.op_str.replace(" ", "") in ("rax,rax", "eax,eax"):
                if "rax" in w.op_str: ptr += 1
                else: err += 1
                break
    if ptr > err: return "xor eax, eax", f"pointer({ptr}/{err})"
    if err > ptr: return "mov eax, 0xc", f"error({err}/{ptr})"
    return "mov eax, 0xc", "no-vote"

# ---- SELF-AUDIT: early closure over stages #0..#1295 ----
def closure(roots):
    fn_of_root, visited = {}, set()
    queue = deque((r, k) for k, r in roots)
    while queue:
        f, root = queue.popleft()
        if f in visited or not (KTEXT <= f < TEXT_HI): continue
        if b"\x55\x48\x89\xe5" not in at(f, 12): continue
        visited.add(f); fn_of_root.setdefault(f, []).append(root)
        try: fins = disasm_fn(f)
        except Exception: continue
        for i in fins:
            t = branch_target(i)
            if t is not None and KTEXT <= t < TEXT_HI and t != 0x9F08AA10:
                queue.append((resolve_entry(t), root))
    return fn_of_root, visited

def stages_roots(lo, hi):
    roots = []
    for k in range(lo, hi):
        p = u64(SET_LO + 8 * k)
        if not (0x9FE73EC0 <= p < 0xA0FF9670) or p == 0 or u32(p) < 2: continue
        f = u64(p + 8)
        if f: roots.append((k, resolve_entry(f)))
    return roots

print("[audit] building early closure (stages #0..#1295) ...")
_, early_fns = closure(stages_roots(0, 1296))
print(f"[audit] early closure: {len(early_fns)} fns — none of these may be patched")

# ---- the 26 G49 sites (tail-only; stage = sysinit attribution) ----
SITES = [
    # (site, fn, stage, static-flags, recipe-hint)
    (0x9E8E244B, 0x9E8E2430, 1303, 0x8102, None),
    (0x9E8E2578, 0x9E8E2430, 1303, 0x102,  None),
    (0x9E8E29CF, 0x9E8E2430, 1303, 0x8102, None),
    (0x9E9478AD, 0x9E947790, 1328, 0x2,    None),
    (0x9ECC4BF5, 0x9ECC4AF0, 1337, 0x102,  None),
    (0x9ECC4C0E, 0x9ECC4AF0, 1337, 0x102,  None),
    (0x9ECC5410, 0x9ECC4AF0, 1337, 0x2,    None),
    (0x9ECC5425, 0x9ECC4AF0, 1337, 0x2,    None),
    (0x9ECC543A, 0x9ECC4AF0, 1337, 0x2,    None),
    (0x9ECC5627, 0x9ECC4AF0, 1337, 0x102,  None),
    (0x9ECC5941, 0x9ECC4AF0, 1337, 0x102,  None),
    (0x9ED9CCBA, 0x9ED9CC60, 1314, 0x8002, None),
    (0x9EDF41D9, 0x9EDF4130, 1296, 0x102,  "R1"),   # THE proven blocker — NULL-tolerant, keep handler inits
    (0x9EDF445C, 0x9EDF4430, 1296, 0x102,  "R2"),   # strncpy(0x20,'DMMYAPPID') if NULL — must bail
    (0x9ED5BD40, 0x9ED5BCA0, 1303, None,   None),   # flags register-sourced; downgrade = no-op unless WAITOK
    (0x9EF149A6, 0x9EF148B0, 1321, 0x8002, None),
    (0x9EF14BDB, 0x9EF148B0, 1321, 0x8002, None),
    (0x9EF14CDA, 0x9EF148B0, 1321, 0x8002, None),
    (0x9EF16396, 0x9EF162B0, 1321, 0x8002, None),
    (0x9EF1644C, 0x9EF162B0, 1321, 0x8002, None),
    (0x9EF1AB32, 0x9EF1AB10, 1321, 0x8102, None),
    (0x9EF1ABA6, 0x9EF1AB10, 1321, 0x8002, None),
    (0x9EF1AC7C, 0x9EF1AB10, 1321, 0x8002, None),
    (0x9EF1DB02, 0x9EF1DAD0, 1321, 0x8002, None),
    (0x9EFFDE05, 0x9EFFDD40, 1328, 0x2,    None),
    (0x9F0873B7, 0x9F0873A0, 1319, 0x102,  None),   # handler itself mallocs first
]

# ---- gate each site, choose recipe, build records ----
# attribution: prologue_back (wide window) gives the REAL owner; the scanner's
# fn may be an overflow artifact. Re-audit the real owner against early_fns.
records, skipped = [], []
for n, (site, fn0, stage, flags, hint) in enumerate(SITES):
    slot = SLOT0 + n * SLOT_STEP
    pb = prologue_back(site)
    if pb is None:
        skipped.append((site, fn0, "no-owner (prologue_back None, wide window)")); continue
    fn = pb
    if fn in early_fns:
        skipped.append((site, fn, f"AUDIT: real owner {fn:#x} early-reachable")); continue
    b5 = at(site, 5)
    rel = (slot - (site + 5)).to_bytes(4, "little", signed=True)
    if b5[:1] == b"\xe8":
        tgt = site + 5 + struct.unpack("<i", b5[1:5])[0]
        if tgt != MALLOC:
            skipped.append((site, fn, f"call target {tgt:#x} != malloc")); continue
    elif b5[:1] == b"\xe9":
        if b5[1:5] != rel:
            skipped.append((site, fn, f"hooked elsewhere: {b5.hex()}")); continue
    else:
        skipped.append((site, fn, f"unexpected bytes {b5.hex()}")); continue
    recipe = hint
    unwind, retcode, vote = None, None, None
    if recipe in (None, "R2"):
        ins = disasm_fn(fn)
        idx = next((j for j, i in enumerate(ins) if i.address == site), None)
        ok = idx is not None
        pr = parse_prologue(fn) if ok else None
        if ok and pr is None: ok = False
        if ok:
            seen, capped = cfg_states(fn, ins)
            target = -(8 * len(pr[0]) + pr[1])
            ok = (idx in seen) and (not capped) and (seen[idx] == {target})
        epi = find_epilogue(ins) if ok else None
        if ok and (epi is None or prologue_back(epi[-1].address + epi[-1].size) != fn):
            ok = False
        if ok:
            pops, addsum, has_leave = epilogue_pops(epi)
            if not prologue_consistent(pr[0], pr[1], pops, addsum, has_leave):
                ok = False
        if ok:
            unwind = [f"{x.mnemonic} {x.op_str}".strip() for x in epi]
            retcode, vote = vote_return(fn)
            if recipe is None: recipe = "R2"
        elif recipe == "R2":
            skipped.append((site, fn, "R2 forced but gates failed")); continue
        else:
            recipe = "R1"
    else:
        recipe = "R1"
    records.append(dict(site=site, fn=fn, stage=stage, flags=flags, slot=slot,
                        recipe=recipe, unwind=unwind, retcode=retcode, vote=vote))
print(f"[gates] {len(records)} guards ready "
      f"(R1={sum(1 for r in records if r['recipe']=='R1')}, "
      f"R2={sum(1 for r in records if r['recipe']=='R2')}); skipped {len(skipped)}")
for s, f, why in skipped:
    print(f"  SKIP {s:#x} fn {f:#x}: {why}")

# ---- apply ----
def apply_guard(r):
    S, SLOT = r["site"], r["slot"]
    rel = (SLOT - (S + 5)).to_bytes(4, "little", signed=True)
    b5 = at(S, 5)
    if b5[:1] == b"\xe8":
        img[S - KTEXT: S - KTEXT + 5] = b"\xe9" + rel
    # build stub
    stub = asm("and edx, 0xfd", SLOT)                      # clear M_WAITOK
    stub += asm(f"call {MALLOC:#x}", SLOT + len(stub))     # real attempt (NOWAIT)
    cont = S + 5
    if r["recipe"] == "R2":
        stub += asm("test rax, rax", SLOT + len(stub))
        # jz rel32 -> skip exactly the 5-byte 'jmp cont' (bail starts right after it)
        stub += bytes([0x0f, 0x84, 0x05, 0x00, 0x00, 0x00])
        stub += asm(f"jmp {cont:#x}", SLOT + len(stub))
        stub += asm(r["retcode"], SLOT + len(stub))
        for u in r["unwind"]:
            stub += asm(u, SLOT + len(stub))
        stub += asm("ret", SLOT + len(stub))
    else:
        stub += asm(f"jmp {cont:#x}", SLOT + len(stub))
    assert len(stub) <= 0x60, f"stub too big @ {SLOT:#x}"
    cur = at(SLOT, len(stub))
    if not all(b == 0xCC for b in cur) and cur != stub:
        sys.exit(f"FAIL slot {SLOT:#x} not pristine: {cur[:16].hex()}")
    img[SLOT - KTEXT: SLOT - KTEXT + len(stub)] = stub
    # verify
    c1 = list(md.disasm(at(S, 5), S))[0]
    assert c1.mnemonic == "jmp" and int(c1.op_str, 16) == SLOT, f"site {S:#x}"
    st = list(md.disasm(stub, SLOT))
    assert st[0].mnemonic == "and" and "edx" in st[0].op_str, f"slot {SLOT:#x}"
    assert st[1].mnemonic == "call" and int(st[1].op_str, 16) == MALLOC, f"slot {SLOT:#x}"
    jm = [i for i in st if i.mnemonic == "jmp"]
    assert jm and (int(jm[-1].op_str, 16) & 0xFFFFFFFF) == cont, f"slot {SLOT:#x} rejoin"
    if r["recipe"] == "R2":
        jzs = [i for i in st if i.mnemonic == "je" or i.mnemonic == "jz"]
        assert jzs, f"slot {SLOT:#x} no bail jz"
    return len(stub)

for r in records:
    n = apply_guard(r)
    r["stub_len"] = n

# ---- G50: park stub direct-0x402 emission ----
PARK, STR, PRINTER = 0x9E404700, 0x9E404740, 0x9E64D410
OLD_STUB = bytes.fromhex("48bf4047409effffffffe8018d2400faf4ebfd")
MSG = b"WP23: sysinit walk complete; parking.\n\x00"
if at(STR, len(MSG)) != MSG:
    img[STR - KTEXT: STR - KTEXT + len(MSG)] = MSG
G50_CODE = f"""
    movabs rsi, {0xFFFFFFFF9E404740:#x}
    mov    dx, 0x402
loop0:
    lodsb
    test   al, al
    jz     done0
    out    dx, al
    jmp    loop0
done0:
    movabs rdi, {0xFFFFFFFF9E404740:#x}
    call   {0xFFFFFFFF9E64D410:#x}
    cli
halt0:
    hlt
    jmp    halt0
"""
g50 = asm(G50_CODE, PARK)
assert len(g50) <= 0x40, f"G50 stub too big: {len(g50):#x}"
area = at(PARK, 0x40)
if area[: len(g50)] == g50:
    pass  # already G50 (idempotent)
elif area[: len(OLD_STUB)] == OLD_STUB:
    pass  # classic G41 stub — rewrite below
else:
    sys.exit(f"FAIL park stub area unexpected: {area[:24].hex()}")
img[PARK - KTEXT: PARK - KTEXT + len(g50)] = g50
st = list(md.disasm(g50, PARK))
outs = [i for i in st if i.mnemonic == "out"]
assert outs and "dx" in outs[0].op_str and "al" in outs[0].op_str, "G50 no out dx,al"
calls = [i for i in st if i.mnemonic == "call"]
assert calls and int(calls[0].op_str, 16) == PRINTER, "G50 printer call"
hlts = [i for i in st if i.mnemonic == "hlt"]
assert hlts, "G50 no hlt"
print(f"OK WP28-G50: park stub 0x9e404700 -> direct 0x402 emission + printf + hlt "
      f"({len(g50)}B, string @0x9e404740 unchanged)")

# ---- report ----
with open("wp28_report.txt", "w") as fp:
    fp.write("WP28 — G49 M_WAITOK livelock guards + G50 park stub 0x402\n")
    fp.write(f"base: {EXPECT} (user-verified G47-only) | "
             f"root cause: stage #1296 canvasmap malloc(M_WAITOK) livelock\n\n")
    fp.write("site        fn         stage flags  recipe slot       unwind / note\n")
    for r in records:
        fl = f"{r['flags']:#x}" if r["flags"] else "reg?"
        unw = "; ".join(r["unwind"]) if r["unwind"] else "(transparent: no-op unless WAITOK)"
        rc = f" ret={r['retcode']}/{r['vote']}" if r["retcode"] else ""
        fp.write(f"{r['site']:#011x} {r['fn']:#011x} #{r['stage']:<4} {fl:<6} "
                 f"{r['recipe']}    {r['slot']:#x} {unw}{rc}\n")
    fp.write(f"\nskipped ({len(skipped)}):\n")
    for s, f, why in skipped:
        fp.write(f"  {s:#x} fn {f:#x}: {why}\n")
    fp.write("\nG50: park stub 0x9E404700 — lodsb/out 0x402 direct emission of\n"
             "  'WP23: sysinit walk complete; parking.\\n' BEFORE the printf call,\n"
             "  then movabs rdi; call 0x9e64d410; cli; hlt loop. String @0x9E404740.\n\n")
    fp.write("KNOWN NEXT-ITERATION RISKS (accepted — G48 family reverted by user):\n"
             "  - M_WAITOK sites in SHARED fns (early-reachable): kproc_create paths\n"
             "    of stages #1300/#1305/#1306/#1307 etc may still block -> GDB rip\n"
             "    will point into malloc's witness-check; report back for WP29.\n"
             "  - R1 sites flow NULL into ENOMEM-era callers: interior-LEA derefs\n"
             "    (e.g. 0x9edf445c guarded R2 here) may crash visibly -> rip report.\n")
print(f"OK report: wp28_report.txt")

open(IMG, "wb").write(img)
h = hashlib.md5(bytes(img)).hexdigest()
assert len(img) == 65224704
print(f"OK {SCRIPT_NAME}: G49 x{len(records)} + G50 — new md5 {h}")
