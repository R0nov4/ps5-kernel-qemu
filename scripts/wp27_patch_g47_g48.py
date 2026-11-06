#!/usr/bin/env python3
"""WP27 — G47 + G48: the interior-LEA NULL-allocation sweep
(_ZERO QEMU / ZERO GDB — static capstone verification only_)

USER BOOT5: all 449 WP26 guards cleared; march reached the very-late
stages (tmpfs/exfatfs/devfs/unionfs registered, lapic calibrated twice,
Timecounters, Session ID, tcp_init) and trapped at

  Fatal trap 12 @ 0xffffffff9ec8c9df, CR2 = 0x90 (WRITE, rsi = 0x50)
  current process = 0 (SceSwapper)

Static chain: fn 0x9e7e0650 (RIB table-head creator — 'rib head lock')
calls allocator 0x9eff8b50 (0x1a0 bytes); the ENOMEM era answers NULL;
the caller computes the INTERIOR pointer 'lea rsi,[rax+0x50]' with NO
NULL check and hands it to the embedded-lock initializer 0x9ec8c9d0,
whose first store 'mov [rsi+0x40], dx' faults at 0x50+0x40 = 0x90.
Both callers of 0x9e7e0650 (0x9e823290, 0x9e9e27f0) test rax right
after the call ('test rax,rax; je') — the function is POINTER-
returning, so the clean bail is rax := NULL, not 0xc.

G47: guard at 0x9e7e0670 — displaces 'lea rsi,[rax+0x50]; mov rdi,rax'
(7B, rip-free), replays them for non-NULL, bails via the function's
own epilogue with rax = 0 for NULL.

G48: the G44 scanner only caught DIRECT derefs of allocator results;
the interior-LEA form (lea R,[rax+K] -> callee writes [R+off]) slipped
through. Automated sweep over the closure of sysinit stages
#1184..#1339 (+ the crash chain): 49 unique sites, deduped by LEA
address, attributed to their real frame via prologue walk-back. Each
gets the A-guard recipe: test rax; NULL -> replicated epilogue with
the function's voted return convention (pointer fns: xor eax,eax;
error fns: mov eax,0xc — voted by inspecting the callers' post-call
'test rax/eax' pattern); non-NULL -> raw-byte replay + byte-exact
rejoin. WP26's three static gates (CFG-exact rsp balance, epilogue
ownership, prologue<->epilogue consistency) protect every bail.

Report-only: BSS-global load -> store-through scan (TAILQ-on-uninit
family) and the WP26-skipped panic adjacency. Slots continue the G46
chain at 0x9E413B00 (pristine CC, ~0x7B00 bytes free). Idempotent."""
import hashlib, re, struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

SCRIPT_NAME = "wp27_patch_g47_g48.py"
KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"
TEXT_HI = 0x9F780000
SET_LO, SET_HI = 0x9FE51FB0, 0x9FE55488
SLOT0, SLOT_STEP = 0x9E413B00, 0x80
EXPECT = "a822c626c50d38a29af2c0a4960d9dae"
ALLOCS = {0x9E82B0E0, 0x9E82B880, 0x9EE30900, 0x9EFF8910, 0x9EFF8B50}
EXCLUDE = ALLOCS | {0x9F08AA10, 0x9EBE1950, 0x9EBE1810, 0x9EAED6B0}
CRASH_FNS = {0x9E7E0650, 0x9E823290, 0x9E9E27F0, 0x9EC8C9D0}

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
    print(f"note: base md5 {h0} (expected {EXPECT} on a fresh WP26 base; "
          f"site-byte checks below enforce idempotent correctness)")
assert len(img) == 65224704

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

def prologue_back(va):
    lo = max(KTEXT, va - 0x800)
    idx = bytes(img).rfind(b"\x55\x48\x89\xe5", lo - KTEXT, va - KTEXT + 1)
    return KTEXT + idx if idx >= 0 else None

def disasm_fn(start, cap=0x800):
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

def rip_target(i):
    m = re.search(r"rip\s*([+-])\s*(0x[0-9a-f]+)", i.op_str)
    if m: return i.address + i.size + int(m.group(2), 16) * (-1 if m.group(1) == "-" else 1)
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
    from collections import deque
    seen, dq, work = {}, deque([(0, 8)]), 0
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

def cfg_delta_check(ins, idx, pushes, subsum, W):
    target = -(8 * len(pushes) + subsum)
    seen, capped = cfg_states(W, ins)
    if idx not in seen: return False, "cfg-unreachable"
    if capped: return False, "cfg-capped"
    bad = {d for d in seen[idx] if d != target}
    return (not bad), f"cfg {sorted(seen[idx])} vs {target}"

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

# ---- one full-text pass: call-site index (for caller voting) ----
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
    """inspect callers' post-call tests: pointer (test rax) vs error (test eax)"""
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

# ---- build the remaining-walk closure (site candidates) ----
roots = []
for k in range(1184, 1340):
    p = u64(SET_LO + 8 * k)
    if not (0x9FE73EC0 <= p < 0xA0FF9670) or p == 0 or u32(p) < 2: continue
    f = u64(p + 8)
    if f: roots.append((k, f))

visited = set()
queue = [(resolve_entry(f), k) for k, f in roots]
while queue:
    f, root = queue.pop(0)
    if f in visited or not (KTEXT <= f < TEXT_HI): continue
    if b"\x55\x48\x89\xe5" not in at(f, 12): continue
    visited.add(f)
    for i in disasm_fn(f):
        t = branch_target(i)
        if t is not None and KTEXT <= t < TEXT_HI and t != 0x9F08AA10:
            queue.append((resolve_entry(t), root))
scan_fns = visited | CRASH_FNS

# ---- find interior-LEA sites: alloc call -> lea R,[rax+K], no NULL check ----
REG64 = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
sites = {}
for f in sorted(scan_fns):
    ins = disasm_fn(f)
    for j, i in enumerate(ins):
        if i.mnemonic != "call": continue
        if branch_target(i) not in ALLOCS: continue
        copies = {"rax"}
        for w in ins[j+1:j+8]:
            if w.mnemonic in ("test", "cmp"):
                if any(c in w.op_str.split(",")[0] for c in copies): break
                continue
            if w.mnemonic == "lea":
                m = re.match(r"(\w+), \[(\w+)", w.op_str)
                if m and m.group(2) in copies:
                    sites.setdefault(w.address, (i.address, w.op_str))
                    break
                continue
            if w.mnemonic == "mov" and w.op_str.count(",") == 1:
                dst, src = [x.strip() for x in w.op_str.split(",")]
                if src in copies and dst in REG64: copies.add(dst)
                elif dst in copies: copies.discard(dst)
            if w.mnemonic in ("call", "jmp", "ret"): break
print(f"closure: {len(visited)} fns | unique interior-LEA sites: {len(sites)}")

# ---- per-site gates + records ----
records, skipped = [], []
for la in sorted(sites):
    ca, ops = sites[la]
    W = prologue_back(la)
    if W is None:
        skipped.append((la, 0, "no-prologue")); continue
    if W in EXCLUDE:
        skipped.append((la, W, "core-excluded")); continue
    ins = disasm_fn(W)
    idx = next((j for j, i in enumerate(ins) if i.address == la), None)
    if idx is None:
        skipped.append((la, W, "site-outside-frame")); continue
    # displaced block: >=5B, no ctrl flow, no rip-relatives
    block, n = [], 0
    for i in ins[idx:]:
        block.append(i); n += i.size
        if n >= 5: break
    if n < 5 or idx + len(block) >= len(ins):
        skipped.append((la, W, "block-too-short")); continue
    if any((i.mnemonic.startswith("j") or i.mnemonic in ("call", "ret")) or
           rip_target(i) is not None for i in block):
        skipped.append((la, W, "block-unrelocatable")); continue
    cont = ins[idx + len(block)].address
    pr = parse_prologue(W)
    if pr is None:
        skipped.append((la, W, "prologue-unparseable")); continue
    ok1, why1 = cfg_delta_check(ins, idx, pr[0], pr[1], W)
    if not ok1:
        skipped.append((la, W, f"rsp-unbalanced({why1})")); continue
    epi = find_epilogue(ins)
    if not epi:
        skipped.append((la, W, "no-epilogue")); continue
    if prologue_back(epi[-1].address + epi[-1].size) != W:
        skipped.append((la, W, "epilogue-ownership")); continue
    pushes, subsum = pr
    pops, addsum, has_leave = epilogue_pops(epi)
    if not prologue_consistent(pushes, subsum, pops, addsum, has_leave):
        skipped.append((la, W, f"prologue-mismatch({pushes}|{subsum} vs {pops}|{addsum})")); continue
    retcode, vote = vote_return(W)
    records.append(dict(site=la, fn=W, alloc_ca=ca, ops=ops,
                        old=b"".join(bytes(i.bytes) for i in block), cont=cont,
                        unwind=[f"{x.mnemonic} {x.op_str}".strip() for x in epi],
                        retcode=retcode, vote=vote))

records.sort(key=lambda r: r["site"])
print(f"gate-passed: {len(records)}  (skipped: {len(skipped)})")

# ---- fallback: call-site guards for lea-site failures (argpush==0 only:
# stack-arg calls would shift their arguments across the extra slot frame) ----
call_records, call_skipped = [], []
vote_cache = {}
for la, _, why in skipped:
    ca = sites[la][0]
    W = prologue_back(ca)
    if W is None:
        call_skipped.append((ca, 0, f"{why} / no-prologue")); continue
    if W in EXCLUDE:
        call_skipped.append((ca, W, f"{why} / core-excluded")); continue
    ins = disasm_fn(W)
    idx = next((j for j, i in enumerate(ins) if i.address == ca), None)
    if idx is None:
        call_skipped.append((ca, W, f"{why} / site-outside-frame")); continue
    pr = parse_prologue(W)
    if pr is None:
        call_skipped.append((ca, W, f"{why} / prologue-unparseable")); continue
    pushes, subsum = pr
    d_frame = -(8 * len(pushes) + subsum)
    seen, capped = cfg_states(W, ins)
    if idx not in seen or capped:
        call_skipped.append((ca, W, f"{why} / cfg")); continue
    ds = seen[idx]
    if len(ds) != 1:
        call_skipped.append((ca, W, f"{why} / multi-delta{sorted(ds)}")); continue
    d = next(iter(ds))
    if d != d_frame:
        call_skipped.append((ca, W, f"{why} / argpush-unsafe({d_frame - d})")); continue
    epi = find_epilogue(ins)
    if not epi:
        call_skipped.append((ca, W, f"{why} / no-epilogue")); continue
    if prologue_back(epi[-1].address + epi[-1].size) != W:
        call_skipped.append((ca, W, f"{why} / epilogue-ownership")); continue
    pops, addsum, has_leave = epilogue_pops(epi)
    if not prologue_consistent(pushes, subsum, pops, addsum, has_leave):
        call_skipped.append((ca, W, f"{why} / prologue-mismatch")); continue
    b5 = at(ca, 5)
    if b5[0:1] != b"\xe8":
        call_skipped.append((ca, W, f"{why} / not-e8")); continue
    alloc = ca + 5 + struct.unpack("<i", b5[1:5])[0]
    if W not in vote_cache:
        vote_cache[W] = vote_return(W)
    retcode, vote = vote_cache[W]
    call_records.append(dict(ca=ca, fn=W, alloc=alloc, lea=la, why=why,
                             unwind=[f"{x.mnemonic} {x.op_str}".strip() for x in epi],
                             retcode=retcode, vote=vote))
call_records.sort(key=lambda r: r["ca"])
print(f"call-site fallback: {len(call_records)} guards  (still skipped: {len(call_skipped)})")

# ---- G47 hand guard (crash site — callers verified pointer-convention) ----
G47 = dict(tag="G47 rib-head 0x9e7e0650 alloc 0x9eff8b50", site=0x9E7E0670,
           slot=0x9E413B00, old="488d70504889c7", cont=0x9E7E0677,
           unwind=["pop rbx", "pop r14", "pop rbp"], retcode="xor eax, eax")
assert any(r["site"] == 0x9E7E0670 and r["fn"] == 0x9E7E0650 for r in records), "G47 site missing from sweep"

# ---- patch G47 + G48 records ----
def patch_guard(g, is_g47=False):
    S, SLOT = g["site"], g["slot"]
    OLD = bytes.fromhex(g["old"]) if isinstance(g["old"], str) else g["old"]
    rel = (SLOT - (S + 5)).to_bytes(4, "little", signed=True)
    site_b = at(S, len(OLD))
    if site_b[:1] == b"\xe9":
        if site_b[1:5] != rel:
            sys.exit(f"FAIL site {S:#x} hooked elsewhere: {site_b.hex()}")
    else:
        if site_b != OLD:
            sys.exit(f"FAIL site {S:#x}: {site_b.hex()} != {OLD.hex()}")
        img[S - KTEXT: S - KTEXT + len(OLD)] = b"\xe9" + rel + b"\x90" * (len(OLD) - 5)
    test = asm("test rax, rax", SLOT)
    jmpb = asm(f"jmp {g['cont']:#x}", SLOT + len(test) + 2 + len(OLD))
    err = asm(g["retcode"], SLOT)
    unw = b"".join(asm(u, SLOT) for u in g["unwind"])
    stub = test + bytes([0x74, len(OLD) + 5]) + OLD + jmpb + err + unw + b"\xc3"
    assert len(stub) <= 0x60, f"stub too big @ {SLOT:#x}"
    cur = at(SLOT, len(stub))
    if not all(b == 0xCC for b in cur) and cur != stub:
        sys.exit(f"FAIL slot {SLOT:#x} not pristine: {cur[:16].hex()}")
    img[SLOT - KTEXT: SLOT - KTEXT + len(stub)] = stub
    c1 = list(md.disasm(at(S, 5), S))[0]
    assert c1.mnemonic == "jmp" and int(c1.op_str, 16) == SLOT, f"site {S:#x}"
    st = list(md.disasm(stub, SLOT))
    assert st[0].mnemonic == "test" and "rax" in st[0].op_str, f"stub {SLOT:#x}"
    assert st[1].mnemonic in ("je", "jz"), f"stub {SLOT:#x} no jz"
    assert stub[len(st[0].bytes) + len(st[1].bytes):][:len(OLD)] == OLD
    jm = [i for i in st if i.mnemonic == "jmp"]
    assert jm and (int(jm[-1].op_str, 16) & 0xFFFFFFFF) == (g["cont"] & 0xFFFFFFFF)
    return len(stub)

n1 = patch_guard(G47)
print(f"OK G47: site 0x9e7e0670 -> slot 0x9e413b00 (NULL-guard rax, ret=NULL, stub {n1:#x}B)")

# idempotency bookkeeping for re-runs on an already-patched image: the
# lea-site guard tolerates e9-hooked sites via patch_guard's rel check;
# the call-site guards below tolerate retargeted e8 via the same check.

patched = 0
for n, r in enumerate(records):
    if r["site"] == 0x9E7E0670:  # already G47
        continue
    g = dict(site=r["site"], slot=SLOT0 + (n + 1) * SLOT_STEP, old=r["old"],
             cont=r["cont"], unwind=r["unwind"], retcode=r["retcode"])
    patch_guard(g)
    patched += 1

# ---- patch the call-site fallback guards ----
def patch_call_guard(g):
    S, SLOT = g["ca"], g["slot"]
    rel = (SLOT - (S + 5)).to_bytes(4, "little", signed=True)
    b5 = at(S, 5)
    cur_tgt = S + 5 + struct.unpack("<i", b5[1:5])[0]
    if b5[0:1] == b"\xe8" and b5[1:5] == rel:
        pass                                          # already patched (idempotent)
    elif b5[0:1] == b"\xe8" and cur_tgt == g["alloc"]:
        pass                                          # fresh allocator call — retarget below
    else:
        sys.exit(f"FAIL call-site {S:#x} unexpected bytes {b5.hex()} -> {cur_tgt:#x}")
    off = 0
    stub = asm(f"call {g['alloc']:#x}", SLOT)
    off += len(stub)
    enc = asm("test rax, rax", SLOT + off)
    stub += enc; off += len(enc)
    stub += bytes([0x74, 1]); off += 2                # jz +1 -> L1 (skip the ret)
    stub += b"\xc3"; off += 1                          # ret (non-NULL: back to caller)
    stub += asm(g["retcode"], SLOT + off); off += len(stub) - off
    stub += asm("add rsp, 8", SLOT + off); off += len(stub) - off
    for u in g["unwind"]:
        stub += asm(u, SLOT + off); off += len(stub) - off
    stub += asm("ret", SLOT + off)
    assert len(stub) <= 0x60, f"stub too big @ {SLOT:#x}"
    cur = at(SLOT, len(stub))
    if not all(b == 0xCC for b in cur) and cur != stub:
        sys.exit(f"FAIL slot {SLOT:#x} not pristine: {cur[:16].hex()}")
    img[SLOT - KTEXT: SLOT - KTEXT + len(stub)] = stub
    img[S - KTEXT + 1: S - KTEXT + 5] = rel             # retarget the e8
    c1 = list(md.disasm(at(S, 5), S))[0]
    assert c1.mnemonic == "call" and int(c1.op_str, 16) == SLOT, f"call-site {S:#x}"
    st = list(md.disasm(stub, SLOT))
    assert st[0].mnemonic == "call" and int(st[0].op_str, 16) == g["alloc"], f"slot {SLOT:#x}"
    assert st[1].mnemonic == "test" and "rax" in st[1].op_str, f"slot {SLOT:#x}"
    assert st[2].mnemonic == "je", f"slot {SLOT:#x}"
    return len(stub)

call_patched = 0
base_n = len(records) + 1
for n, r in enumerate(call_records):
    g = dict(ca=r["ca"], slot=SLOT0 + (base_n + n) * SLOT_STEP, alloc=r["alloc"],
             unwind=r["unwind"], retcode=r["retcode"])
    patch_call_guard(g)
    call_patched += 1

# ---- report ----
with open("wp27_g48_report.txt", "w") as fp:
    fp.write(f"WP27 G48 interior-LEA sweep — {patched+1} guards (G47 + {patched}), "
             f"{len(skipped)} skipped\n")
    fp.write(f"closure: {len(visited)} fns; unique sites {len(sites)}\n\n")
    fp.write("G47 (hand): site 0x9e7e0670 fn 0x9e7e0650 alloc@0x9e7e066b "
             "-> lea rsi,[rax+0x50]; ret=NULL; unwind pop rbx; pop r14; pop rbp\n\n")
    fp.write("site        fn          alloc@      displaced -> rejoin  unwind <- real epilogue        ret / vote\n")
    for n, r in enumerate(records):
        slot = SLOT0 if r["site"] == 0x9E7E0670 else SLOT0 + (n + 1) * SLOT_STEP
        fp.write(f"{r['site']:#011x} {r['fn']:#011x} {r['alloc_ca']:#011x} "
                 f"{r['old'].hex()[:16]:<16}->{r['cont']:#x} "
                 f"{'; '.join(r['unwind'])[:40]:<40} {r['retcode']} / {r['vote']} slot {slot:#x}\n")
    fp.write("\nskipped:\n")
    for s, f, why in skipped:
        fp.write(f"  {s:#x} fn {f:#x}: {why}\n")
    fp.write("\ncall-site fallback guards (lea-site failed; allocator call retargeted\n"
             "to slot: call ALLOC; test rax; ret | NULL: retcode; add rsp,8; epilogue; ret):\n")
    for n, r in enumerate(call_records):
        slot = SLOT0 + (base_n + n) * SLOT_STEP
        fp.write(f"  alloc-call {r['ca']:#x} fn {r['fn']:#x} -> {r['alloc']:#x} "
                 f"(lea {r['lea']:#x}: {r['why']}) ret={r['retcode']} / {r['vote']} "
                 f"unwind {'; '.join(r['unwind'])[:40]} slot {slot:#x}\n")
    for s, f, why in call_skipped:
        fp.write(f"  STILL-SKIPPED alloc-call {s:#x} fn {f:#x}: {why}\n")
    # report-only: WP26-skipped panic adjacency
    rep = open("wp26_g46_report.txt").read() if __import__("os").path.exists("wp26_g46_report.txt") else ""
    if rep:
        sk = re.findall(r"0x([0-9a-f]+) fn 0x([0-9a-f]+): (.+)",
                        rep.split("skipped:")[1].split("crossmp global")[0])
        ins = [(int(s, 16), int(f, 16), r2) for s, f, r2 in sk if int(f, 16) in scan_fns]
        fp.write(f"\nWP26-skipped panic sites whose fn is in this closure: {len(ins)} "
                 f"(none fired in user boot5 — the boot died on a page fault, not a panic;\n"
                 f"the frame-known ones were already B-diverted in WP26)\n")
        for s, f, r2 in ins[:60]:
            fp.write(f"  {s:#x} fn {f:#x}: {r2}\n")
    # report-only: BSS-global load -> store-through (TAILQ-on-uninit family)
    fp.write("\nreport-only BSS scan (load [rip+X] with zero image bytes -> store through it):\n")
    bss_hits = 0
    store_tgts = set()
    for m in re.finditer(rb"(?:\x48|\x4c)\x89[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", img[:TEXT_HI - KTEXT]):
        p = m.start()
        store_tgts.add(KTEXT + p + 7 + struct.unpack("<i", img[p+3:p+7])[0])
    for m in re.finditer(rb"\xc7\x05", img[:TEXT_HI - KTEXT]):
        p = m.start()
        store_tgts.add(KTEXT + p + 10 + struct.unpack("<i", img[p+2:p+6])[0])
    for f in sorted(visited):
        fins = disasm_fn(f)
        for j, i in enumerate(fins):
            if i.mnemonic != "mov" or not re.match(r"r\w+, qword ptr \[rip", i.op_str or ""):
                continue
            g = rip_target(i)
            if g is None or g in store_tgts or g - KTEXT + 8 > len(img):
                continue
            if any(img[g - KTEXT + q] for q in range(8)):
                continue  # non-zero image bytes (.data initialized)
            reg = i.op_str.split(",")[0].strip()
            for w in fins[j+1:j+4]:
                if w.mnemonic == "test" and reg in w.op_str:
                    break
                if w.mnemonic == "mov" and "," in w.op_str and \
                        re.search(r"\[r\w+\]", w.op_str.split(",")[0]):
                    bss_hits += 1
                    fp.write(f"  fn {f:#x}: load {i.address:#x} global {g:#x} (never stored) "
                             f"-> store-through {w.address:#x} {w.mnemonic} {w.op_str}\n")
                    break
    fp.write(f"  total: {bss_hits} (false positives possible — runtime-initialized globals; review before guarding)\n")

print(f"OK G48: {patched} lea-site + {call_patched} call-site guards (slots {SLOT0 + SLOT_STEP:#x}.."
      f"{SLOT0 + (base_n + len(call_records)) * SLOT_STEP:#x})")
print(f"report: wp27_g48_report.txt | lea-skip {len(skipped)} | call-skip {len(call_skipped)}")

open(IMG, "wb").write(img)
h = hashlib.md5(bytes(img)).hexdigest()
assert len(img) == 65224704
print(f"OK {SCRIPT_NAME}: G47 + G48({patched + call_patched}) — new md5 {h}")
