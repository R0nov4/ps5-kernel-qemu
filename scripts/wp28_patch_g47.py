#!/usr/bin/env python3
"""WP28 step 1 — G47-only re-application (byte-exact the USER-VERIFIED build).

The WP27 G48 sweep is DISCARDED (regression: its first guard sat in
0x9e6b6eb0 above the WP16-FIX#7 cave48 at 0x9e6b6ef1 and bailed the
kmem_suballoc constructor with rax=0 before the cave could run ->
'panic: kmem_suballoc: cannot create submap').

G47 alone (user boot6: zero crashes, zero panics, 45s quiet — march
stuck INSIDE stage #1296's canvasmap malloc(M_WAITOK) — see WP28):
  site 0x9e7e0670 'lea rsi,[rax+0x50]; mov rdi,rax' (7B) -> jmp slot
  slot 0x9E413B00: test rax,rax; jz +0xc; <orig 7B>; jmp 0x9e7e0677;
                    xor eax,eax; pop rbx; pop r14; pop rbp; ret

GATE: md5 must equal 175a002cf7665ff88bb43a04241a6d95 (the image the
user booted on their laptop). ZERO QEMU / ZERO GDB.
"""
import hashlib, struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"
ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        sys.exit(f"ASM FAILED @ {base:#x}: {code}")
    return bytes(enc)

G47 = dict(site=0x9E7E0670, slot=0x9E413B00,
           old=bytes.fromhex("488d70504889c7"), cont=0x9E7E0677,
           unwind=["pop rbx", "pop r14", "pop rbp"], retcode="xor eax, eax")
EXPECT_BASE = "a822c626c50d38a29af2c0a4960d9dae"   # WP26
EXPECT_OUT  = "175a002cf7665ff88bb43a04241a6d95"   # user-verified G47-only

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704
h0 = hashlib.md5(bytes(img)).hexdigest()

def at(va, n): return bytes(img[va - KTEXT: va - KTEXT + n])

def patch_guard(g):
    S, SLOT = g["site"], g["slot"]
    OLD = g["old"]
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
    assert st[0].mnemonic == "test" and "rax" in st[0].op_str
    assert st[1].mnemonic in ("je", "jz")
    assert stub[len(st[0].bytes) + len(st[1].bytes):][:len(OLD)] == OLD
    jm = [i for i in st if i.mnemonic == "jmp"]
    assert jm and (int(jm[-1].op_str, 16) & 0xFFFFFFFF) == (g["cont"] & 0xFFFFFFFF)
    return len(stub)

if h0 != EXPECT_BASE and h0 != EXPECT_OUT:
    print(f"note: base md5 {h0} (expected WP26 {EXPECT_BASE} or G47 {EXPECT_OUT})")
n = patch_guard(G47)
open(IMG, "wb").write(img)
h = hashlib.md5(bytes(img)).hexdigest()
print(f"OK WP28-G47: site 0x9e7e0670 -> slot 0x9e413b00 (NULL-guard rax, ret=NULL, stub {n:#x}B)")
print(f"OK WP28-G47: md5 {h}")
if h != EXPECT_OUT:
    sys.exit(f"!! G47 GATE FAIL — expected {EXPECT_OUT}")
print("OK G47 GATE: 175a002cf7665ff88bb43a04241a6d95 (user-verified image)")
