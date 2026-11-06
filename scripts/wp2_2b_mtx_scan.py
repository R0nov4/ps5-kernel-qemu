#!/usr/bin/env python3
"""WP2 STEP 2b (v2) — STRICT struct mtx scan.
Real held mutex: mtx_lock = owner_thread_ptr | flags(0..7),
owner must be a valid kernel VA in [thread0/static, runtime heap).
Free = 4 (written by mtx_init). String tables have tiny 'lock' values -> rejected.
"""
import sys, re
sys.path.insert(0, "./scripts")
import wp1_lib as L
import numpy as np
from collections import Counter

D0, D1 = L.DATA_BASE, 0xFFFFFFFFA2224000
img = L._blob[L.va2off(D0): L.va2off(D1)]
q = np.frombuffer(img, dtype="<u8")

NAME_LO, NAME_HI = 0xFFFFFFFF9E600000, 0xFFFFFFFFA0C00000
THREAD_LO, THREAD_HI = 0xFFFFFFFFA1800000, 0xFFFFFFFFA46B0000

_strcache = {}
def get_name(v):
    if v not in _strcache:
        _strcache[v] = L.cstr(v, 48)
    return _strcache[v]

NAME_RE = re.compile(r"^[A-Za-z0-9_ ./:\-()&+]{3,48}$")

mtx = []
n = len(q)
for i in range(n - 3):
    namep = int(q[i])
    if not (NAME_LO <= namep < NAME_HI):
        continue
    v08 = int(q[i+1])
    v10 = int(q[i+2])
    v18 = int(q[i+3])
    recurse = v08 >> 32
    if recurse > 0xFFFF:
        continue
    # lo_flags (+8 low32): 0 or flag-ish (>=0x10000) — reject tiny enum values
    loflags = v08 & 0xFFFFFFFF
    if 0 < loflags < 0x10000:
        continue
    # +0x10 (witness/list): 0 or plausible kernel ptr
    if v10 != 0 and not (0xFFFFFFFF9E000000 <= v10 < 0xFFFFFFFFA46B0000):
        continue
    # mtx_lock: 0 (uninit), 4 (free), or owner-thread|flags
    if v18 == 0 or v18 == 4:
        state = "free" if v18 == 4 else "zero"
    else:
        owner = v18 & 0xFFFFFFFFFFFFFFF8
        flags = v18 & 7
        if THREAD_LO <= owner < THREAD_HI and flags <= 3:
            state = "LOCKED"
        else:
            continue
    s = get_name(namep)
    if not s or not NAME_RE.match(s):
        continue
    mtx.append((D0 + i * 8, s, v18, loflags, recurse, state))

cnt = Counter(m[5] for m in mtx)
print(f"struct mtx found (strict): {len(mtx)}   states: {dict(cnt)}")
locked = [m for m in mtx if m[5] == "LOCKED"]
print(f"\n=== {len(locked)} REALLY-HELD MUTEXES AT DUMP TIME ===")
for base, s, v18, loflags, rec, _st in sorted(locked):
    owner = v18 & ~7
    flags = v18 & 7
    tag = ""
    if flags & 1: tag += " RECURSED"
    if flags & 2: tag += " CONTESTED"
    print(f"  mtx @0x{base:x}  '{s}'  lock=0x{v18:x}  owner=0x{owner:x}{tag}")

print(f"\n=== distribution of held-mutex owner threads ===")
oc = Counter((m[2] & ~7) for m in locked)
for owner, c in oc.most_common(20):
    print(f"  owner 0x{owner:x}: holds {c} mutexes")

# save machine-readable
import json
out = [ {"va": hex(b), "name": s, "mtx_lock": hex(v), "flags": hex(f), "recurse": r}
        for b, s, v, f, r, st in locked ]
json.dump(out, open("./download/ps5_wp2/wp2_held_mutexes.json", "w"), indent=1)
print("\nsaved download/ps5_wp2/wp2_held_mutexes.json")
