#!/usr/bin/env python3
"""wp10_analyze.py — WP10 forensics on the MADT registry loop.

Sub-commands:
  refs <va>          scan .text for RIP-relative refs (lea/mov/cmp...) to VA
  walk [head]        walk the static handler list from head (default 0xa19d3b80)
  node <va>          pretty-print a handler node {name, fns, next}
"""
import sys, struct
import capstone

DUMP = "./ps5/dump13/kernel-13.60-live.bin"
KTEXT = 0xffffffff9e3f0000
KDATA = 0xffffffff9f0b0000
DATA_FOFF = 0xCC0000

with open(DUMP, "rb") as f:
    IMG = f.read()

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

def off(va):
    va &= 0xffffffffffffffff
    return va - KTEXT

def q(va):
    return struct.unpack_from("<Q", IMG, off(va))[0]

def d(va):
    return struct.unpack_from("<I", IMG, off(va))[0]

def cstr(va, maxlen=64):
    b = IMG[off(va):off(va)+maxlen]
    return b.split(b"\0")[0].decode("utf-8", "replace")

def refs(target):
    """Scan the whole .text for RIP-relative instructions targeting `target`."""
    target &= 0xffffffffffffffff
    results = []
    text = IMG[:DATA_FOFF]
    # crude linear sweep with capstone over each 16-byte-aligned window start is
    # unreliable; instead decode forward from every 0x1000 boundary with resync
    # on direct refs. Faster: scan raw bytes for common rip-rel encodings then
    # validate by decoding around.
    CHUNK = 0x10000
    for base in range(0, DATA_FOFF, CHUNK):
        code = text[base:base+CHUNK]
        for ins in md.disasm(code, KTEXT + base):
            # find rip-relative memory operands
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    tgt = ins.address + ins.size + op.mem.disp
                    if tgt == target:
                        results.append((ins.address, ins.mnemonic, ins.op_str))
    return results

def node_str(va):
    name_p = q(va)
    try:
        name = cstr(name_p, 24)
    except Exception:
        name = "??"
    fns = [q(va+8+i*8) for i in range(4)]
    nxt = q(va+0x28)
    extra = q(va+0x30)
    s = f"node {va:#x}: name='{name}' (str@{name_p:#x})\n"
    for i, f in enumerate(fns):
        s += f"  +0x{8+i*8:02x} fn{i} = {f:#x}"
        # resolve thunk jmp if it's a 5-byte rel jmp
        o = off(f)
        if IMG[o] == 0xE9:
            rel = struct.unpack_from("<i", IMG, o+1)[0]
            s += f"  -> thunk -> {f+5+rel:#x}"
        s += "\n"
    s += f"  +0x28 next = {nxt:#x}\n  +0x30 val  = {extra:#x}"
    return s

def walk(head=0xffffffffa19d3b80, maxn=32):
    cur = q(head)
    print(f"head [{head:#x}] = {cur:#x}")
    seen = set()
    n = 0
    while cur and n < maxn:
        print("--- node #%d ---" % n)
        print(node_str(cur))
        if cur in seen:
            print("*** CYCLE back to", hex(cur), "***")
            break
        seen.add(cur)
        cur = q(cur + 0x28)
        n += 1
    if cur is None or cur == 0:
        print("list ends at NULL after", n, "nodes")

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    if cmd == "refs":
        t = int(sys.argv[2], 0)
        rs = refs(t)
        if not rs:
            print("no rip-relative refs found to", hex(t))
        for a, m, o in rs:
            print(f"{a:#018x}  {m} {o}")
    elif cmd == "walk":
        h = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0xffffffffa19d3b80
        walk(h)
    elif cmd == "node":
        print(node_str(int(sys.argv[2], 0)))
    else:
        print(__doc__)
