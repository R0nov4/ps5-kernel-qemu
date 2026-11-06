#!/usr/bin/env python3
"""WP26 — G45 + G46: panic-block neutralization, remaining sysinit walk
(_ZERO QEMU / ZERO GDB — static capstone verification only_)

G45 (crossmp panic): fn 0x9e9ea8f0 calls the G43-guarded constructor
0x9e937f60; its ENOMEM-era 0xc now trips 'jne 0x9e9ea9bb' ->
"failed to allocate crossmp?" panic (certain power-down). Redirect the
jne to the function's own epilogue (0x9e9ea9b4: add rsp,0x28; pop rbx;
pop rbp; ret) — rax still carries 0xc; the whole post-error body
(mtx_init + crossmp +0xb8/+0x8 derefs) is skipped, so the nulled
crossmp global is never touched on the diverted path. The success path
(ctor ret 0 -> out-param set non-NULL) is untouched.

G46 (remaining-walk panic sweep): closure of sysinit stages #1184..#1339
(level-1 handler + 2 callee levels, prologue-validated entries). Every
'call/jmp 0x9f08aa10' site in the closure (minus the allocator / panic /
witness cores) gets the B-divert: 5-byte call -> 'jmp slot', slot =
'mov eax,0xc' + the containing function's own real epilogue + 'ret'
(unwind extracted from the actual epilogue instruction run, never
guessed). Slots continue the G44 chain at 0x9E405B00 (pristine CC,
4410 free). Idempotent + byte-verified."""
import hashlib, re, struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

SCRIPT_NAME = "wp26_patch_g45_g46.py"
KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"
PANIC = 0x9F08AA10
SET_LO, SET_HI = 0x9FE51FB0, 0x9FE55488
SLOT0, SLOT_STEP = 0x9E405B00, 0x80
DEPTH = 5
TEXT_HI = 0x9F780000
EXPECT = "5d438a939e327950884e8e97289d18a6"
KW = re.compile(r"(init|alloc|creat|attach|sbl|mp|fe)", re.I)
# allocator cores / panic core / witness-mDBG logger cores: never divert these
EXCLUDE = {0x9E82B0E0, 0x9E82B880, 0x9EE30900, 0x9EFF8910, 0x9EFF8B50,
           0x9F08AA10, 0x9EBE1950, 0x9EBE1810, 0x9EAED6B0}
CROSSMP_G = (0x9FAC15E0, 0x9FAC15E8)

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        raise RuntimeError(f"ASM FAILED @ {base:#x}: {code}")
    return bytes(enc)

img = bytearray(open(IMG, "rb").read())
h0 = hashlib.md5(bytes(img)).hexdigest()
if h0 != EXPECT:
    print(f"note: base md5 {h0} (expected {EXPECT} on a fresh WP25 base; "
          f"site-byte checks below enforce idempotent correctness)")
assert len(img) == 65224704

def at(va, n):
    return bytes(img[va - KTEXT: va - KTEXT + n])

def u64(va):
    return struct.unpack("<Q", at(va, 8))[0] & 0xFFFFFFFF

def u32(va):
    return struct.unpack("<I", at(va, 4))[0]

def prologue_back(va):
    lo = max(KTEXT, va - 0x800)
    idx = bytes(img).rfind(b"\x55\x48\x89\xe5", lo - KTEXT, va - KTEXT + 1)
    return KTEXT + idx if idx >= 0 else None

def padding_run(va, n=8):
    b = at(va, n)
    return len(b) == n and all(c in (0xCC, 0x90) for c in b)

def disasm_fn(start, cap=0x3000):
    out = []
    for i in md.disasm(at(start, cap), start):
        out.append(i)
        if padding_run(i.address + i.size, 8):
            break
    return out

def parse_prologue(W):
    """pushes after 'push rbp; mov rbp,rsp' + summed sub rsp; None if unusable"""
    ins = list(md.disasm(at(W, 48), W))
    if not ins or ins[0].mnemonic != "push" or ins[0].op_str != "rbp":
        return None
    if len(ins) < 2 or ins[1].mnemonic != "mov" or ins[1].op_str != "rbp, rsp":
        return None
    pushes, subsum, k = [], 0, 2
    while k < len(ins):
        i = ins[k]
        if i.mnemonic == "push":
            pushes.append(i.op_str)
        elif i.mnemonic == "sub" and i.op_str.startswith("rsp,"):
            try:
                subsum += int(i.op_str.split(",")[1].strip(), 0)
            except ValueError:
                return None
        else:
            break
        k += 1
    return pushes, subsum

def epilogue_pops(epi):
    pops, addsum, leave = [], 0, False
    for x in epi:
        if x.mnemonic == "pop":
            pops.append(x.op_str)
        elif x.mnemonic == "add" and x.op_str.startswith("rsp,"):
            addsum += int(x.op_str.split(",")[1].strip(), 0)
        elif x.mnemonic == "leave":
            leave = True
    return pops, addsum, leave

def prologue_consistent(pushes, subsum, pops, addsum, has_leave):
    """accepts full-pop epilogues AND 'add rsp,8' alignment-skip forms"""
    popped = [r for r in pops if r != "rbp"]
    if not all(r in pushes for r in popped):
        return False
    if not ("rbp" in pops or has_leave):
        return False
    slack = 8 * len([r for r in pushes if r not in pops])
    if has_leave:
        return not pushes and addsum == subsum == 0
    return addsum == subsum + slack

def rsp_delta(i):
    if i.mnemonic == "push":
        return -8
    if i.mnemonic == "pop":
        return 8
    if i.mnemonic == "sub" and i.op_str.startswith("rsp,"):
        return -int(i.op_str.split(",")[1].strip(), 0)
    if i.mnemonic == "add" and i.op_str.startswith("rsp,"):
        return int(i.op_str.split(",")[1].strip(), 0)
    return 0

_cfg_states_cache = {}

def cfg_states(W, ins):
    """BFS over (instruction, rsp-rbp delta) with hard caps; cached per function"""
    if W in _cfg_states_cache:
        return _cfg_states_cache[W]
    byaddr = {i.address: j for j, i in enumerate(ins)}
    def succ(j):
        i = ins[j]
        if i.mnemonic == "jmp":
            if i.op_str.startswith("0x") and int(i.op_str, 16) in byaddr:
                return [byaddr[int(i.op_str, 16)]]
            return []
        if i.mnemonic == "ret":
            return []
        if i.mnemonic.startswith("j") and i.op_str.startswith("0x"):
            out = []
            t = int(i.op_str, 16)
            if t in byaddr:
                out.append(byaddr[t])
            if j + 1 < len(ins):
                out.append(j + 1)
            return out
        return [j + 1] if j + 1 < len(ins) else []
    from collections import deque
    seen = {}
    dq = deque([(0, 8)])            # state BEFORE 'push rbp': rsp = rbp_frame+8 (retaddr)
    work = 0
    CAP_WORK, CAP_DELTA = 200000, 0x4000
    while dq and work < CAP_WORK:
        j, d = dq.popleft()
        work += 1
        if j >= len(ins) or abs(d) > CAP_DELTA or (j in seen and d in seen[j]):
            continue
        seen.setdefault(j, set()).add(d)
        if ins[j].mnemonic == "ret":
            continue
        nd = d + rsp_delta(ins[j])
        for nj in succ(j):
            dq.append((nj, nd))
    _cfg_states_cache[W] = (seen, work >= CAP_WORK)
    return _cfg_states_cache[W]

def cfg_delta_check(ins, idx, pushes, subsum, W):
    """every CFG path from the frame prologue to ins[idx] must carry
    rsp-rbp == -(8*len(pushes)+subsum); unreachable/capped -> skip"""
    target = -(8 * len(pushes) + subsum)
    seen, capped = cfg_states(W, ins)
    if idx not in seen:
        return False, "cfg-unreachable"
    if capped:
        return False, "cfg-capped"
    bad = {d for d in seen[idx] if d != target}
    return (not bad), f"cfg {sorted(seen[idx])} vs {target}"

def branch_target(i):
    if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
        try:
            return int(i.op_str, 16)
        except ValueError:
            return None
    return None

def lea_target(i):
    if i.mnemonic != "lea" or not i.op_str.startswith("rsi,"):
        return None
    m = re.search(r"rip\s*([+-])\s*(0x[0-9a-f]+)", i.op_str)
    if m:
        rel = int(m.group(2), 16) * (-1 if m.group(1) == "-" else 1)
        return i.address + i.size + rel
    m = re.search(r"\[0x([0-9a-f]+)\]", i.op_str)
    if m:
        return int(m.group(1), 16)
    if "rip]" in i.op_str:
        return i.address + i.size
    return None

def mem_target(i):
    m = re.search(r"rip\s*([+-])\s*(0x[0-9a-f]+)", i.op_str)
    if m:
        rel = int(m.group(2), 16) * (-1 if m.group(1) == "-" else 1)
        return i.address + i.size + rel
    return None

def cstr(va, maxlen=64):
    out = bytearray()
    off = va - KTEXT
    while len(out) < maxlen and 0 <= off < len(img):
        c = img[off + len(out)]
        if c == 0:
            break
        out.append(c)
    try:
        s = out.decode("ascii")
    except UnicodeDecodeError:
        return "<bin>"
    return s if s and all(32 <= ord(ch) < 127 for ch in s) else "<bin>"

def resolve_entry(f, hops=4):
    """follow jmp-thunk entries (sysinit handlers sit behind e9 rel32 thunks)"""
    seen = set()
    while hops > 0 and f not in seen:
        seen.add(f)
        b = at(f, 5)
        if b[0:1] == b"\xe9":
            t = f + 5 + struct.unpack("<i", b[1:5])[0]
            if KTEXT <= t < TEXT_HI:
                f = t
                hops -= 1
                continue
        break
    return f

def find_epilogue(insns):
    """last complete (pop*/add rsp/leave)+ret run that restores rbp"""
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
            if run and any(x.mnemonic in ("leave",) or
                           (x.mnemonic == "pop" and x.op_str == "rbp") for x in run):
                best = run          # keep scanning; we want the LAST one
        k -= 1
    return best

# =========================================================================
print("=== G45: crossmp panic -> clean epilogue (jne 0x9e9ea9bb -> 0x9e9ea9b4) ===")
JNE, EPI = 0x9E9EA94F, 0x9E9EA9B4
site = at(JNE, 2)
if site == bytes.fromhex("756a"):
    img[JNE - KTEXT: JNE - KTEXT + 2] = bytes.fromhex("7563")
    print("OK G45 jne redirected: 756a -> 7563 (target 0x9e9ea9b4, rax=0xc kept)")
elif site == bytes.fromhex("7563"):
    print("OK G45 already applied (idempotent)")
else:
    sys.exit(f"FAIL G45 site bytes: {site.hex()}")
chk = list(md.disasm(at(JNE, 2), JNE))[0]
assert chk.mnemonic == "jne" and int(chk.op_str, 16) == EPI, "G45 verify failed"
epi_b = at(EPI, 7)
assert epi_b == bytes.fromhex("4883c4285b5dc3"), f"G45 epilogue bytes: {epi_b.hex()}"

# =========================================================================
print("=== G46: closure scan of sysinit stages #1184..#1339 ===")
roots = []
for k in range(1184, 1340):
    p = u64(SET_LO + 8 * k)
    if not (0x9FE73EC0 <= p < 0xA0FF9670) or p == 0:
        continue
    if u32(p) < 2:                       # dummies / done
        continue
    f = u64(p + 8)
    if f:
        roots.append((k, f))
print(f"roots: {len(roots)} stages with live handlers")

visited, panic_sites, xmp_users = set(), [], []
queue = [(resolve_entry(f), 1, k) for k, f in roots]
fn_of_root = {}
while queue:
    f, d, root = queue.pop(0)
    if f in visited or not (KTEXT <= f < TEXT_HI):
        continue
    if b"\x55\x48\x89\xe5" not in at(f, 12):
        continue                          # need a frame-pointer prologue for the unwind
    visited.add(f)
    fn_of_root.setdefault(f, root)
    insns = disasm_fn(f)
    for i in insns:
        t = branch_target(i)
        if t is not None:
            if t == PANIC and i.size == 5:
                panic_sites.append((i.address, f, i.mnemonic))
            elif d < DEPTH and KTEXT <= t < TEXT_HI:
                queue.append((resolve_entry(t), d + 1, root))
        mt = mem_target(i)
        if mt in CROSSMP_G:
            xmp_users.append((f, i.address, i.mnemonic + " " + i.op_str))

print(f"closure: {len(visited)} functions (depth {DEPTH})")
print(f"crossmp fn 0x9e9ea8f0 in closure: {0x9E9EA8F0 in visited}")
print(f"raw panic sites: {len(panic_sites)}")

# ---- per-site: attribute frame, extract epilogue, gates, fmt string ----
records, skipped = [], []
seen_site = set()
for site_va, scan_fn, mnem in panic_sites:
    if site_va in seen_site:
        continue
    seen_site.add(site_va)
    W = prologue_back(site_va)
    if W is None:
        skipped.append((site_va, scan_fn, "no-prologue"))
        continue
    if W in EXCLUDE:
        skipped.append((site_va, W, "core-excluded"))
        continue
    ins = disasm_fn(W)
    idx = next((j for j, i in enumerate(ins) if i.address == site_va), None)
    if idx is None:
        skipped.append((site_va, W, "site-outside-frame"))
        continue
    # gate 1: CFG-exact rsp balance from frame start to the site
    pr_early = parse_prologue(W)
    if pr_early is None:
        skipped.append((site_va, W, "prologue-unparseable"))
        continue
    ok1, why1 = cfg_delta_check(ins, idx, pr_early[0], pr_early[1], W)
    if not ok1:
        skipped.append((site_va, W, f"rsp-unbalanced({why1})"))
        continue
    epi = find_epilogue(ins)
    if not epi:
        skipped.append((site_va, W, "no-epilogue"))
        continue
    # gate 2: epilogue must belong to W's frame (own function)
    if prologue_back(epi[-1].address + epi[-1].size) != W:
        skipped.append((site_va, W, "epilogue-ownership"))
        continue
    # gate 3: prologue <-> epilogue consistency (rax-skip aware)
    pushes, subsum = pr_early
    pops, addsum, has_leave = epilogue_pops(epi)
    if not prologue_consistent(pushes, subsum, pops, addsum, has_leave):
        skipped.append((site_va, W, f"prologue-mismatch({pushes}|{subsum} vs {pops}|{addsum})"))
        continue
    # fmt string: last lea rsi,[rip+..] within 12 instrs before the call
    fmt = "<no fmt>"
    for i in reversed(ins[max(0, idx - 12):idx]):
        lt = lea_target(i)
        if lt is not None and KTEXT <= lt < KTEXT + len(img):
            fmt = cstr(lt)
            break
    records.append(dict(site=site_va, fn=W, root=fn_of_root.get(scan_fn, -1),
                        fmt=fmt, kw=bool(KW.search(fmt)),
                        unwind=[f"{x.mnemonic} {x.op_str}".strip() for x in epi]))

records.sort(key=lambda r: r["site"])
print(f"patchable panic sites: {len(records)}  (skipped: {len(skipped)})")

# ---- assign slots + patch ----
def slot_of(i):
    return SLOT0 + i * SLOT_STEP

patched = 0
for n, r in enumerate(records):
    S, SLOT = r["site"], slot_of(n)
    old = at(S, 5)
    rel = (SLOT - (S + 5)).to_bytes(4, "little", signed=True)
    if old[0:1] == b"\xe9":
        if old[1:5] != rel:
            sys.exit(f"FAIL site {S:#x} hooked elsewhere: {old.hex()}")
    else:
        t = S + 5 + struct.unpack("<i", old[1:5])[0]
        if old[0:1] not in (b"\xe8", b"\xe9") or t != PANIC or len(old) != 5:
            sys.exit(f"FAIL site {S:#x} unexpected bytes {old.hex()}")
        img[S - KTEXT: S - KTEXT + 5] = b"\xe9" + rel
    stub = asm("mov eax, 0xc", SLOT)
    for u in r["unwind"]:
        stub += asm(u, SLOT + len(stub))
    stub += asm("ret", SLOT + len(stub))
    assert len(stub) <= 0x60, f"stub too big @ {SLOT:#x}"
    cur = at(SLOT, len(stub))
    if not all(b == 0xCC for b in cur) and cur != stub:
        sys.exit(f"FAIL slot {SLOT:#x} not pristine: {cur[:16].hex()}")
    img[SLOT - KTEXT: SLOT - KTEXT + len(stub)] = stub
    # static re-verify
    c1 = list(md.disasm(at(S, 5), S))[0]
    assert c1.mnemonic == "jmp" and int(c1.op_str, 16) == SLOT, f"site {S:#x}"
    c2 = list(md.disasm(at(SLOT, 6), SLOT))[0]
    assert c2.mnemonic == "mov" and c2.op_str.startswith("eax,"), f"slot {SLOT:#x}"
    patched += 1

# ---- report ----
with open("wp26_g46_report.txt", "w") as fp:
    fp.write(f"WP26 G46 panic sweep — {len(records)} sites patched, {len(skipped)} skipped\n")
    fp.write(f"closure: {len(visited)} fns from {len(roots)} stage roots (#1184..#1339)\n\n")
    fp.write("site        fn          stage  kw  unwind <- real epilogue      fmt\n")
    for n, r in enumerate(records):
        fp.write(f"{r['site']:#011x} {r['fn']:#011x} #{r['root']:<5} "
                 f"{'Y' if r['kw'] else '.'}   {'; '.join(r['unwind'])[:44]:<44} {r['fmt'][:44]}\n")
    fp.write("\nskipped:\n")
    for s, f, why in skipped:
        fp.write(f"  {s:#x} fn {f:#x}: {why}\n")
    fp.write("\ncrossmp global users in closure:\n")
    for f, a, op in xmp_users:
        fp.write(f"  fn {f:#x} @ {a:#x}: {op}\n")

print(f"OK G46: {patched} panic sites B-diverted (slots {SLOT0:#x}..{slot_of(len(records)-1):#x})")
print(f"report: wp26_g46_report.txt | skipped {len(skipped)} | crossmp-global users {len(xmp_users)}")

open(IMG, "wb").write(img)
h = hashlib.md5(bytes(img)).hexdigest()
assert len(img) == 65224704
print(f"OK {SCRIPT_NAME}: G45 + G46({patched}) — new md5 {h}")
