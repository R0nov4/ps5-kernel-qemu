#!/usr/bin/env python3
"""WP29 — REPORT-ONLY scan: retry-on-NULL loops in the tail-stage closure.
Pattern: call <fn> ; test rax,rax ; je/jz BACKWARD (to <= call site) —
i.e. the caller re-invokes on NULL. Also: unconditional backward jumps
right after a NULL-test. No patches (the WP27-G48 lesson: no speculative
guards) — this is the pre-triage shortlist for the next boot log."""
import re, struct
from collections import deque
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

K = 0x9E3F0000
TEXT_HI = 0x9F780000
SET_LO = 0x9FE51FB0
img = open("wp3_boot/kernel_raw.bin", "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

def at(va, n): return img[va - K: va - K + n]
def u64(va): return struct.unpack("<Q", at(va, 8))[0] & 0xFFFFFFFF
def u32(va): return struct.unpack("<I", at(va, 4))[0]
def resolve(f, h=6):
    seen = set()
    while h > 0 and f not in seen:
        seen.add(f); b = at(f, 5)
        if b[0:1] == b"\xe9":
            t = f + 5 + struct.unpack("<i", b[1:5])[0]
            if K <= t < TEXT_HI: f = t; h -= 1; continue
        break
    return f
def padding_run(va, n=8):
    b = at(va, n)
    return len(b) == n and all(c in (0xCC, 0x90) for c in b)
def prologue_back(va, w=0x1000):
    lo = max(K, va - w)
    idx = bytes(img).rfind(b"\x55\x48\x89\xe5", lo - K, va - K + 1)
    return K + idx if idx >= 0 else None
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

# closure of stages #1266..#1339 (the un-walked tail after the fixed #1266)
roots = []
for k in range(1266, 1340):
    p = u64(SET_LO + 8 * k)
    if not (0x9FE73EC0 <= p < 0xA0FF9670) or p == 0 or u32(p) < 2: continue
    h = u64(p + 8)
    if h == 0: h = u64(p + 0x18)     # alt handler
    if h: roots.append((k, resolve(h)))
visited, fn_of_root = set(), {}
q = deque((f, k) for k, f in roots)
while q:
    f, root = q.popleft()
    if f in visited or not (K <= f < TEXT_HI): continue
    if b"\x55\x48\x89\xe5" not in at(f, 12): continue
    visited.add(f); fn_of_root.setdefault(f, []).append(root)
    try: fins = disasm_fn(f)
    except Exception: continue
    for i in fins:
        t = branch_target(i)
        if t is not None and K <= t < TEXT_HI and t != 0x9F08AA10:
            q.append((resolve(t), root))
print(f"tail closure (#1266..#1339 roots: {len(roots)}): {len(visited)} fns")

def cstr(va, m=48):
    out = bytearray(); off = va - K
    while len(out) < m and 0 <= off < len(img):
        c = img[off + len(out)]
        if c == 0: break
        out.append(c)
    try: s = out.decode("ascii")
    except UnicodeDecodeError: return None
    return s if s and all(32 <= ord(ch) < 127 for ch in s) else None

print("\n=== call -> test rax -> BACKWARD conditional (retry-on-NULL suspects) ===")
hits = 0
for f in sorted(visited):
    try: ins = disasm_fn(f)
    except Exception: continue
    for j, i in enumerate(ins):
        if i.mnemonic != "call": continue
        # look at the next 3 instructions for a NULL-test + backward branch
        for w in ins[j+1:j+4]:
            if w.mnemonic in ("call", "jmp"):
                break
            if w.mnemonic == "test" and w.op_str.replace(" ", "") in ("rax,rax", "eax,eax"):
                for b in ins[j+2:j+5]:
                    if b.mnemonic in ("je", "jz") and b.op_str.startswith("0x"):
                        t = int(b.op_str, 16)
                        if t <= i.address and t >= f:
                            hits += 1
                            print(f"  fn {f:#x} stages={fn_of_root.get(f)}: call@{i.address:#x}"
                                  f" -> {resolve(int(i.op_str,16)) if i.op_str.startswith('0x') else i.op_str};"
                                  f" test@{w.address:#x}; BACK-jz to {t:#x}")
                        break
                break
print(f"total suspects: {hits}")
print("\n(no patches applied — report only; the next boot log triages these)")
