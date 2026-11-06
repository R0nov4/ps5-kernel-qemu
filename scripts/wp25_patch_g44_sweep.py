#!/usr/bin/env python3
"""WP25 G44 — the remaining-walk preemptive NULL-allocation sweep (x23)

The sysinit queue after the BAPM stage (#1184, '[BAPM] C0 wc param')
holds 155 more entries (#1185..#1339) before the G41 end-of-walk park
('WP23: sysinit walk complete; parking.'). Static closure scan of all
155 handler trees (3319 functions, allocator family = the empirically
NULL-returning 0x9e82b0e0 / 0x9e82b880(->0x9ee30900) / 0x9eff8910 /
0x9eff8b50) found 22 more 'call allocator -> deref without NULL check'
sites (the G42/G43 crash family) plus one checked allocation whose
NULL path is a panic block (fn 0x9e6b7210: test rax,rax / je
0x9e6b72b1 = call 0x9ebe1950 + log + panic 0x9f08aa10 + ud2).

All 22 deref sites get the G43 recipe (test the base reg, raw-byte
replay of the displaced instruction(s), NULL -> replicated epilogue +
'mov eax,0xc'); every containing function's unwind is derived from its
hand-verified prologue (all 19 prologues eyeballed: push rbp; mov
rbp,rsp; pushes/sub-rsp). The panic block gets a B-divert: the 5-byte
'call 0x9ebe1950' at its head becomes a jmp to a bail stub (same
unwind + 0xc) — panic (certain stop) becomes error-return (chance to
march on). Checked-but-printing blocks (0x9e8dba26, 0x9ed67a63,
0x9ed67bd7: printer + 'mov eax,0xc/1' + ret) are already benign error
paths and were deliberately LEFT ALONE.

Slots 0x9E404F00..0x9E405A80 (pristine CC). Idempotent, zero QEMU,
zero GDB — the boot verification is the user's own run.sh test."""

SCRIPT_NAME = "wp25_patch_g44_sweep.py"

GUARDS = [
    dict(tag='fn 0x9e6b7210 alloc 0x9e82b880', site=0X9E6B725D, slot=0X9E404F00, old='48899818010000', unwind=['pop rax', 'pop rbx', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9E6B7264),
    dict(tag='fn 0x9e6c0300 alloc 0x9e82b880', site=0X9E6C03BD, slot=0X9E404F80, old='4c8968304989c4', unwind=['pop rax', 'pop rbx', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9E6C03C4),
    dict(tag='fn 0x9e7b60f0 alloc 0x9e82b880', site=0X9E7B6208, slot=0X9E405000, old='48890848895008', unwind=['add rsp, 24', 'pop rbx', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9E7B620F),
    dict(tag='fn 0x9e82c0c0 alloc 0x9e82b880', site=0X9E82C6A3, slot=0X9E405080, old='48c7400800000000', unwind=['add rsp, 88', 'pop rbx', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9E82C6AB),
    dict(tag='fn 0x9e8f0910 alloc 0x9e82b880', site=0X9E8F09A4, slot=0X9E405100, old='48894b0848c7431000000000', unwind=['pop rax', 'pop rbx', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'pop rbp'], reg='rbx', cont=0XFFFFFFFF9E8F09B0),
    dict(tag='fn 0x9e8f0c90 alloc 0x9e82b880', site=0X9E8F0D75, slot=0X9E405180, old='4c89204c897808', unwind=['add rsp, 184', 'pop rbx', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9E8F0D7C),
    dict(tag='fn 0x9e8f0c90 alloc 0x9e82b880', site=0X9E8F0FD8, slot=0X9E405200, old='c780100300000c000000', unwind=['add rsp, 184', 'pop rbx', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9E8F0FE2),
    dict(tag='fn 0x9e8f0c90 alloc 0x9e82b880', site=0X9E8F137D, slot=0X9E405280, old='488908488b8d50ffffff', unwind=['add rsp, 184', 'pop rbx', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9E8F1387),
    dict(tag='fn 0x9e923500 alloc 0x9eff8b50', site=0X9E923526, slot=0X9E405300, old='48c70000000000', unwind=['pop rax', 'pop rbx', 'pop r14', 'pop r15', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9E92352D),
    dict(tag='fn 0x9e947120 alloc 0x9eff8b50', site=0X9E9471AD, slot=0X9E405400, old='4c89700848c70000000000', unwind=['add rsp, 24', 'pop rbx', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9E9471B8),
    dict(tag='fn 0x9e947120 alloc 0x9eff8b50', site=0X9E94723C, slot=0X9E405480, old='4889184889c2', unwind=['add rsp, 24', 'pop rbx', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9E947242),
    dict(tag='fn 0x9e947120 alloc 0x9eff8b50', site=0X9E947289, slot=0X9E405500, old='4889184889c2', unwind=['add rsp, 24', 'pop rbx', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9E94728F),
    dict(tag='fn 0x9e9523d0 alloc 0x9eff8b50', site=0X9E9523FD, slot=0X9E405580, old='c780a40c000001000000', unwind=['pop rax', 'pop rbx', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9E952407),
    dict(tag='fn 0x9ea66790 alloc 0x9eff8b50', site=0X9EA667EC, slot=0X9E405600, old='4489384989c4', unwind=['pop rax', 'pop rbx', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9EA667F2),
    dict(tag='fn 0x9eae8160 alloc 0x9eff8b50', site=0X9EAE81BB, slot=0X9E405680, old='448970184989c7', unwind=['add rsp, 16', 'pop rbx', 'pop r12', 'pop r14', 'pop r15', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9EAE81C2),
    dict(tag='fn 0x9eae82e0 alloc 0x9eff8b50', site=0X9EAE8343, slot=0X9E405700, old='4889581031f6', unwind=['add rsp, 24', 'pop rbx', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9EAE8349),
    dict(tag='fn 0x9eb1c880 alloc 0x9e82b880', site=0X9EB1C8F7, slot=0X9E405780, old='c7402801000000', unwind=['pop rbx', 'pop r12', 'pop r14', 'pop r15', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9EB1C8FE),
    dict(tag='fn 0x9eb1cbd0 alloc 0x9e82b880', site=0X9EB1CC5E, slot=0X9E405800, old='c7402801000000', unwind=['pop rax', 'pop rbx', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9EB1CC65),
    dict(tag='fn 0x9eb1cf40 alloc 0x9eff8b50', site=0X9EB1CF9C, slot=0X9E405880, old='448930488d7808', unwind=['add rsp, 40', 'pop rbx', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9EB1CFA3),
    dict(tag='fn 0x9eb1f270 alloc 0x9eff8b50', site=0X9EB1F29D, slot=0X9E405900, old='48c70001000000', unwind=['pop rbx', 'pop r12', 'pop r14', 'pop r15', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9EB1F2A4),
    dict(tag='fn 0x9eb6f670 alloc 0x9eff8b50', site=0X9EB6F6E1, slot=0X9E405980, old='4c89384c896808', unwind=['add rsp, 24', 'pop rbx', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9EB6F6E8),
    dict(tag='fn 0x9f024980 alloc 0x9e82b880', site=0X9F0249A2, slot=0X9E405A00, old='4c89304989c7', unwind=['pop rax', 'pop rbx', 'pop r14', 'pop r15', 'pop rbp'], reg='rax', cont=0XFFFFFFFF9F0249A8),
    dict(tag='B-divert panic block (fn 0x9e6b7210, je 0x9e6b727c)', site=0X9E6B72B1, slot=0X9E405A80, old='e89aa65200', unwind=['pop rax', 'pop rbx', 'pop rbp']),
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
