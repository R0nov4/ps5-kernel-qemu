#!/usr/bin/env python3
"""WP28 — deep look at each tail-only M_WAITOK site + tail-only sleepers + #1319."""
import re, struct, json
from collections import deque
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT  = 0x9E3F0000
TEXT_HI= 0x9F780000
SET_LO = 0x9FE51FB0
img = open("wp3_boot/kernel_raw.bin", "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
ALLOCS = {0x9E82B0E0, 0x9E82B880, 0x9EE30900, 0x9EFF8910, 0x9EFF8B50}
SLEEPCK = 0x9F00A3E0

def at(va, n): return img[va - KTEXT: va - KTEXT + n]
def u64(va): return struct.unpack("<Q", at(va, 8))[0] & 0xFFFFFFFF
def u32(va): return struct.unpack("<I", at(va, 4))[0]
def cstr(va, maxlen=64):
    out = bytearray(); off = va - KTEXT
    while len(out) < maxlen and 0 <= off < len(img):
        c = img[off + len(out)]
        if c == 0: break
        out.append(c)
    try: s = out.decode("ascii")
    except UnicodeDecodeError: return None
    return s if s and all(32 <= ord(ch) < 127 for ch in s) else None
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
def rip_target(i):
    m = re.search(r"rip\s*([+-])\s*(0x[0-9a-f]+)", i.op_str)
    if m: return i.address + i.size + int(m.group(2), 16) * (-1 if m.group(1) == "-" else 1)
    return None

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

_, early_fns = closure(stages_roots(0, 1296))
fn_of_root, tail_fns = closure(stages_roots(1296, 1340))
tail_only = tail_fns - early_fns

hits = json.load(open("wp28_alloc_hits.json"))
wait_to = [h for h in hits if h["flags"] not in (None, -1, "None", "-1")
           and (int(h["flags"]) & 2) and not h["shared"]]

print("=== A. tail-only M_WAITOK sites: context ===")
for h in sorted(wait_to, key=lambda x: int(x["site"])):
    site, fn = int(h["site"]), int(h["fn"])
    ins = disasm_fn(fn)
    idx = next((j for j, i in enumerate(ins) if i.address == site), None)
    if idx is None: continue
    print(f"\n--- site {site:#x} fn {fn:#x} flags={h['flags']} stages={h['stages']} ---")
    for i in ins[max(0, idx-6):idx+10]:
        note = ""
        rt = rip_target(i)
        if rt is not None and "rip" in i.op_str:
            s = cstr(rt)
            note = f"  ; rip->{rt:#x}" + (f" {s!r}" if s else "")
        bt = branch_target(i)
        if bt is not None: note += f"  ; ->{resolve_entry(bt):#x}"
        mark = " <<CALL" if i.address == site else ""
        print(f"  {i.address:#x}: {i.mnemonic} {i.op_str}{note}{mark}")

print("\n=== B. tail-only fns that call the sleep-check 0x9f00a3e0 ===")
for f in sorted(tail_only):
    ins = disasm_fn(f)
    for i in ins:
        if i.mnemonic == "call" and branch_target(i) == SLEEPCK:
            # find the wmesg lea just before
            wmsg = None
            for w in reversed(ins[:0] + []): pass
            j = next(jj for jj, x in enumerate(ins) if x.address == i.address)
            for w in ins[max(0,j-6):j]:
                rt = rip_target(w)
                if w.mnemonic == "lea" and rt is not None:
                    s = cstr(rt)
                    if s: wmsg = s
            loops = sum(1 for x in ins if x.mnemonic.startswith("j")
                        and x.op_str.startswith("0x") and int(x.op_str, 16) < x.address)
            print(f"  fn {f:#x} stages={fn_of_root.get(f)} call@{i.address:#x} wmesg={wmsg!r} loops={loops} size={len(ins)}i")

print("\n=== C. handler #1319 (tmr_viol_spin) ===")
for i in disasm_fn(0x9F0873A0, 0x100):
    note = ""
    rt = rip_target(i)
    if rt is not None and "rip" in i.op_str:
        s = cstr(rt)
        note = f"  ; rip->{rt:#x}" + (f" {s!r}" if s else "")
    bt = branch_target(i)
    if bt is not None: note += f"  ; ->{resolve_entry(bt):#x}"
    print(f"  {i.address:#x}: {i.mnemonic} {i.op_str}{note}")
