#!/usr/bin/env python3
"""WP28 — blocking-site scan over stages #1296..#1339 closure.

A site is a BLOCKING candidate if it calls one of the 5 kernel allocators
with statically-known flags having M_WAITOK (bit 1) set — the malloc top
then runs the sleep-check (0x9f00a3e0, GDB-stuck fn) and the M_WAITOK
retry path livelocks in the ENOMEM era.

Exclusion rule (the WP27-G48 regression lesson): a function reachable
from ANY already-executed stage (#0..#1295) must never be patched.
Report: tail-only vs shared, post-call NULL tolerance.
"""
import re, struct
from collections import deque
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT  = 0x9E3F0000
TEXT_HI= 0x9F780000
SET_LO = 0x9FE51FB0
img = open("wp3_boot/kernel_raw.bin", "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
ALLOCS = {0x9E82B0E0, 0x9E82B880, 0x9EE30900, 0x9EFF8910, 0x9EFF8B50}

def at(va, n): return img[va - KTEXT: va - KTEXT + n]
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
def disasm_fn(start, cap=0x1000):
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

# --- first: do the other allocators share the M_WAITOK sleep-check top? ---
print("=== allocator tops (M_WAITOK check?) ===")
for a in sorted(ALLOCS):
    ins = disasm_fn(a, 0x60)
    has_wait = any(i.mnemonic == "call" and branch_target(i) == 0x9F00A3E0 for i in ins)
    print(f"  {a:#x}: {len(ins)}i first-blocks; calls-stuck-fn={has_wait}")
    for i in ins[:14]:
        print(f"    {i.address:#x}: {i.mnemonic} {i.op_str}")

def stages_roots(lo, hi):
    roots = []
    for k in range(lo, hi):
        p = u64(SET_LO + 8 * k)
        if not (0x9FE73EC0 <= p < 0xA0FF9670) or p == 0 or u32(p) < 2: continue
        f = u64(p + 8)
        if f: roots.append((k, resolve_entry(f)))
    return roots

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

# early closure: ALL stages that have ALREADY executed (#0..#1295)
early_root_list = stages_roots(0, 1296)
print(f"\nearly roots (#0..#1295): {len(early_root_list)}")
_, early_fns = closure(early_root_list)
print(f"early closure: {len(early_fns)} fns (NEVER PATCH THESE)")

tail_roots = stages_roots(1296, 1340)
fn_of_root, tail_fns = closure(tail_roots)
print(f"tail roots (#1296..#1339): {len(tail_roots)}  closure: {len(tail_fns)} fns")
tail_only = tail_fns - early_fns
print(f"tail-ONLY fns (safe to patch): {len(tail_only)}")

# --- scan: allocator calls with static M_WAITOK flags ---
print("\n=== allocator call sites in tail closure ===")
REG64 = {"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15"}
hits = []
for f in sorted(tail_fns):
    try: ins = disasm_fn(f)
    except Exception: continue
    for j, i in enumerate(ins):
        if i.mnemonic != "call": continue
        bt = branch_target(i)
        if bt not in ALLOCS: continue
        # propagate edx backwards (stop at call/ret/jmp-unknown)
        flags = None; src = None
        for w in reversed(ins[max(0, j-14):j]):
            if w.mnemonic in ("call", "ret"): break
            if w.mnemonic == "jmp": break
            ops = w.op_str.replace(" ", "")
            if w.mnemonic == "mov" and ops.startswith("edx,"):
                m = re.match(r"edx,(0x[0-9a-f]+|\d+)$", ops)
                if m: flags = int(m.group(1), 0); src = f"mov edx,{m.group(1)}"
                else: flags = -1; src = f"mov {ops}"          # register source — unknown
                break
            if w.mnemonic == "xor" and ops == "edx,edx":
                flags = 0; src = "xor edx,edx"; break
            if w.mnemonic == "or" and ops.startswith("edx,") and flags is None:
                m = re.match(r"edx,(0x[0-9a-f]+|\d+)$", ops)
                if m: flags = int(m.group(1), 0); src = f"or edx,{m.group(1)}"; break
            if w.mnemonic in ("push","pop") and "rdx" in ops: flags = -1; src = ops; break
        if flags is None:
            src = "edx-not-set-locally"
        shared = f in early_fns
        # post-call tolerance: what does the caller do with rax?
        post = []
        for w in ins[j+1:j+6]:
            post.append(f"{w.mnemonic} {w.op_str}")
            if w.mnemonic in ("call", "jmp", "ret"): break
        hits.append(dict(site=i.address, fn=f, alloc=bt, flags=flags, src=src,
                         shared=shared, stages=fn_of_root.get(f), post=post))

wait_hits = [h for h in hits if h["flags"] is not None and h["flags"] != -1 and (h["flags"] & 2)]
unk_hits  = [h for h in hits if h["flags"] in (None, -1)]
ok_hits   = [h for h in hits if h["flags"] is not None and h["flags"] != -1 and not (h["flags"] & 2)]

print(f"\nM_WAITOK sites (BLOCKING candidates): {len(wait_hits)}")
for h in wait_hits:
    tag = "SHARED-EARLY!!" if h["shared"] else "tail-only"
    print(f"  {h['site']:#x} fn {h['fn']:#x} alloc {h['alloc']:#x} flags={h['flags']:#x} ({h['src']}) {tag} stages={h['stages']}")
    print(f"      post: {'; '.join(h['post'])}")
print(f"\nnon-blocking (flags w/o WAITOK): {len(ok_hits)}")
for h in ok_hits:
    tag = "shared" if h["shared"] else "tail-only"
    print(f"  {h['site']:#x} fn {h['fn']:#x} flags={h['flags']:#x} {tag}")
print(f"\nflags-unknown sites (manual review): {len(unk_hits)}")
for h in unk_hits:
    tag = "SHARED" if h["shared"] else "tail-only"
    print(f"  {h['site']:#x} fn {h['fn']:#x} alloc {h['alloc']:#x} ({h['src']}) {tag} stages={h['stages']}")
    print(f"      post: {'; '.join(h['post'])}")

# save machine-readable
import json
json.dump([{k: (v if not isinstance(v, list) else v) for k, v in h.items()} for h in hits],
          open("wp28_alloc_hits.json", "w"), indent=1, default=str)
print("\nsaved wp28_alloc_hits.json")
