#!/usr/bin/env python3
"""wp10_sysinit.py — scan the sysinit_set pointer array in the live dump.

Prints slots in array order (= real machine execution order), resolving thunk
functions, and can filter for specific func targets.
"""
import sys, struct

DUMP = "./ps5/dump13/kernel-13.60-live.bin"
KTEXT = 0xffffffff9e3f0000
SET_BEGIN = 0xffffffff9fe51fb0
SET_END   = 0xffffffff9fe55488

with open(DUMP, "rb") as f:
    IMG = f.read()

def off(va):
    return (va & 0xffffffffffffffff) - KTEXT

def q(va):
    return struct.unpack_from("<Q", IMG, off(va))[0]

def d(va):
    return struct.unpack_from("<I", IMG, off(va))[0]

def resolve_fn(fn):
    """if fn is a 5-byte rel32 jmp thunk, resolve to target"""
    o = off(fn)
    if 0 <= o and o + 5 <= len(IMG) and IMG[o] == 0xE9:
        rel = struct.unpack_from("<i", IMG, o + 1)[0]
        return fn + 5 + rel
    return None

def cstr(va, maxlen=40):
    try:
        b = IMG[off(va):off(va)+maxlen]
        return b.split(b"\0")[0].decode("utf-8", "replace")
    except Exception:
        return "??"

def main():
    n_slots = (SET_END - SET_BEGIN) // 8
    print(f"sysinit_set: [{SET_BEGIN:#x}, {SET_END:#x}) = {n_slots} pointer slots")
    targets = set(int(a, 0) for a in sys.argv[1:]) if len(sys.argv) > 1 else None
    shown = 0
    for i in range(n_slots):
        node = q(SET_BEGIN + i*8)
        if node == 0:
            continue
        try:
            si_sub = d(node)
            si_order = d(node + 4)
            func = q(node + 8)
            udata = q(node + 0x10)
        except Exception:
            print(f"slot {i:4d}: node {node:#x} UNREADABLE")
            continue
        real = resolve_fn(func)
        disp = func
        if real is not None:
            disp = real
        if targets is not None:
            if func in targets or real in targets:
                print(f"slot {i:4d}: node {node:#x} sub={si_sub:#x} order={si_order:#x} "
                      f"func={func:#x} (-> {disp:#x}) udata={udata:#x}")
        else:
            if shown < 12:
                print(f"slot {i:4d}: node {node:#x} sub={si_sub:#x} order={si_order:#x} "
                      f"func={func:#x} (-> {disp:#x}) udata={udata:#x}")
                shown += 1
    if targets is None:
        print("(showing first 12 slots only; pass func VAs as args to filter)")

if __name__ == "__main__":
    main()
