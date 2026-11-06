#!/usr/bin/env python3
"""WP25 G43 — the 0x9e9380c7 / CR2=0xb8 NULL-allocation guard (user boot3 crash)

User's laptop boot3 (WP24 image 697f2632...): the march cleared
'[BAPM] C0 wc param' (sysinit entry #1184, handler 0x9ea5d530) and a
later entry died at

  Fatal trap 12 @ 0xffffffff9e9380c7, CR2 = 0xb8  (READ, rax == NULL)
  current process = 0 (SceSwapper)

Static chain: fn 0x9e937f60 (object constructor, out-param in rcx/rbx)
calls the allocator 0x9e82b880 (jmp-thunk of 0x9ee30900) at 0x9e9380c2
with esi=0, edx=2; the ENOMEM era answers NULL; the first body use
'mov rcx,[rax+0xb8]' faults. All 21 callers test eax right after the
call (17 directly; verified sample 0x9e842fac: nonzero -> designed
error path that NULLs the out-param, saves the code and bails), so a
clean in-function guard is the whole fix: NULL -> replicated epilogue
+ 'mov eax,0xc' (12 = ENOMEM, the family's own convention — sister
block 0x9e8dba26 returns exactly 0xc on allocation failure).

Sister scan of 0x9e937000..0x9e93a000 with the allocator family
{0x9e82b0e0, 0x9e82b880, 0x9eff8910, 0x9eff8b50}: no other unchecked
member — the remaining family lives further out and is swept by G44.

Site 0x9e9380c7 -> slot 0x9E404E80 (pristine CC, right after the G42
block 0x9E404C00..0x9E404E00). Idempotent, byte-exact rejoin for every
non-NULL allocation (raw-byte replay, flags preserved)."""

SCRIPT_NAME = "wp25_patch_g43_nullguard.py"

GUARDS = [
    dict(tag='fn 0x9e937f60 alloc 0x9e82b880', site=0X9E9380C7, slot=0X9E404E80, old='488b88b8000000', unwind=['add rsp, 16', 'pop rbx', 'pop r12', 'pop r14', 'pop r15', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9E9380CE),
]

import sys, hashlib
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}: {code}"); sys.exit(1)
    return bytes(enc)

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

def parse(u):
    return str(u)

for g in GUARDS:
    S, SLOT, OLD = g["site"], g["slot"], bytes.fromhex(g["old"])
    UNW = [parse(u) for u in g["unwind"]]
    rel_expect = (SLOT - (S + 5)).to_bytes(4, "little", signed=True)
    off = S - KTEXT
    site = bytes(img[off:off + len(OLD)])
    if site[:1] == b"\xe9":
        if site[1:5] != rel_expect:
            print(f"FAIL site {S:#x} hooked elsewhere: {site.hex()}"); sys.exit(1)
        hooked = True
    else:
        if site != OLD:
            print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
        hooked = False

    if "reg" in g:      # A-guard: test + replay + rejoin
        test = asm(f"test {g['reg']}, {g['reg']}", SLOT)
        jmpb = asm(f"jmp {g['cont']:#x}", SLOT + len(test) + 2 + len(OLD))
        err = asm("mov eax, 0xc", SLOT)
        unw = b"".join(asm(u, SLOT) for u in UNW)
        stub = test + bytes([0x74, len(OLD) + 5]) + OLD + jmpb + err + unw + b"\xc3"
    else:               # B-divert: unconditional bail
        err = asm("mov eax, 0xc", SLOT)
        unw = b"".join(asm(u, SLOT) for u in UNW)
        stub = err + unw + b"\xc3"
    assert len(stub) <= 0x60, f"stub too big: {len(stub):#x} @ {SLOT:#x}"

    off2 = SLOT - KTEXT
    cur = bytes(img[off2:off2 + len(stub)])
    if not all(b == 0xCC for b in cur) and cur != stub:
        print(f"FAIL slot {SLOT:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)

    img[off2:off2 + len(stub)] = stub
    if not hooked:
        off = S - KTEXT
        img[off:off + len(OLD)] = b"\xe9" + rel_expect + b"\x90" * (len(OLD) - 5)

    # static re-verify
    chk = [i for i in md.disasm(bytes(img[S - KTEXT:S - KTEXT + 8]), S)][:1]
    assert chk and chk[0].mnemonic == "jmp" and int(chk[0].op_str, 16) == SLOT, f"site {S:#x}"
    if "reg" in g:
        st = [i for i in md.disasm(stub, SLOT)]
        assert st[0].mnemonic == "test" and g["reg"] in st[0].op_str, f"stub {SLOT:#x}"
        assert st[1].mnemonic in ("je", "jz"), f"stub {SLOT:#x} no jz"
        # replayed block must be the displaced bytes byte-for-byte
        assert stub[len(st[0].bytes) + len(st[1].bytes):][:len(OLD)] == OLD
        # jmp back target
        jm = [i for i in st if i.mnemonic == "jmp"]
        assert jm and (int(jm[-1].op_str, 16) & 0xFFFFFFFF) == (g["cont"] & 0xFFFFFFFF), f"stub {SLOT:#x} cont"
    else:
        st = [i for i in md.disasm(stub, SLOT)]
        assert st[0].mnemonic == "mov" and st[0].op_str.startswith("eax,"), f"stub {SLOT:#x}"
    kind = ("NULL-guard " + g["reg"]) if "reg" in g else "B-divert bail"
    print(f"OK {g['tag']}: site {S:#x} -> slot {SLOT:#x} ({kind}, stub {len(stub):#x}B)")

open(IMG, "wb").write(img)
h = hashlib.md5(bytes(img)).hexdigest()
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK {SCRIPT_NAME}: {len(GUARDS)} guards — new md5 {h}")
