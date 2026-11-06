#!/usr/bin/env python3
"""WP24 G42 — the NULL-zone accessor family guard x5  (user boot2 crash site)

User's laptop boot2 (WP23 image f1cedeee...): the march passes
'acm: MOD_LOAD error 5' and '[BAPM] C0 wc param' and dies at

  Fatal trap 12 @ 0xffffffff9e82d71e, CR2 = 0x68  (READ, rdi == NULL)
  current process = 0 (SceSwapper)

Call chain (static): fn 0x9e6b5f00 (BAPM family) calls the allocator
0x9e82b0e0, stores rax to a global, then calls 0x9e82d710(rdi=rax, esi=0xa).
The allocator answered NULL (the ENOMEM era: mca taskq 12, camera 12,
acm error 5) -> the accessor's first body load 'mov rax,[rdi+0x68]'
faults on 0x68. The caller IGNORES the accessor's return (goes straight
to the next allocation) -> a clean in-function guard is the whole fix.

GUARDS (the WP18#12 zone-setter recipe, 5th..9th members of the family):
  site         displaced (replayed verbatim)          slot
  0x9e82d71e   mov rax,[rdi+0x68]; test rax,rax   ->  0x9E404C00  (MAIN)
  0x9e82d26a   mov rax,[rdi+0x68]; xor ebx,ebx    ->  0x9E404C80
  0x9e82d44b   mov rax,[rdi+0x68]; xor r14d,r14d  ->  0x9E404D00
  0x9e82e069   and eax,[rdi+0xc8]                 ->  0x9E404D80
  0x9e82e139   mov rsi,[rdi+8]; mov rdi,[rdi+0x20]->  0x9E404E00
NULL zone -> the replicated epilogue + 'xor eax,eax' (identical to each
function's own failure-path return: eax=0); non-NULL -> replay + jmp back
to the instruction right after the displaced block. Flags reaching the
original 'test/je' pairs are produced by the replayed instructions, so
byte-equivalent behaviour for every non-NULL zone.
"""
import sys
import hashlib
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"
MD5_IN = "f1cedeeefdc7e1cf8ad403b1df8a3575"          # WP23 gold (G41 applied)

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

GUARDS = [
    dict(tag="d710 MAIN (CR2=0x68 crash)", site=0x9E82D71E, slot=0x9E404C00,
         old="488b47684885c0",
         replay="mov rax, qword ptr [rdi + 0x68]\ntest rax, rax",
         cont=0xFFFFFFFF9E82D725,
         null="add rsp, 8\npop rbx\npop r12\npop r13\npop r14\npop r15\npop rbp\nxor eax, eax\nret"),
    dict(tag="d260 sibling", site=0x9E82D26A, slot=0x9E404C80,
         old="488b476831db",
         replay="mov rax, qword ptr [rdi + 0x68]\nxor ebx, ebx",
         cont=0xFFFFFFFF9E82D270,
         null="add rsp, 8\npop rbx\npop r14\npop r15\npop rbp\nxor eax, eax\nret"),
    dict(tag="d440 sibling", site=0x9E82D44B, slot=0x9E404D00,
         old="488b47684531f6",
         replay="mov rax, qword ptr [rdi + 0x68]\nxor r14d, r14d",
         cont=0xFFFFFFFF9E82D452,
         null="pop rbx\npop r12\npop r14\npop r15\npop rbp\nxor eax, eax\nret"),
    dict(tag="e060 sibling", site=0x9E82E069, slot=0x9E404D80,
         old="2387c8000000",
         replay="and eax, dword ptr [rdi + 0xc8]",
         cont=0xFFFFFFFF9E82E06F,
         null="pop rbp\nxor eax, eax\nret"),
    dict(tag="e130 sibling", site=0x9E82E139, slot=0x9E404E00,
         old="488b7708488b7f20",
         replay="mov rsi, qword ptr [rdi + 8]\nmov rdi, qword ptr [rdi + 0x20]",
         cont=0xFFFFFFFF9E82E141,
         null="add rsp, 8\npop rbx\npop rbp\nxor eax, eax\nret"),
]

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

for g in GUARDS:
    S, SLOT, OLD = g["site"], g["slot"], bytes.fromhex(g["old"])
    C = f"""
        test rdi, rdi
        jz   nullzone
        {g['replay']}
        jmp  {g['cont']:#x}
    nullzone:
        {g['null']}
    """
    code = asm(C, SLOT)
    assert len(code) <= 0x60, f"stub too big: {len(code):#x}"

    off = S - KTEXT
    site = bytes(img[off:off + len(OLD)])
    rel_expect = (SLOT - (S + 5)).to_bytes(4, "little", signed=True)
    if site[:1] == b"\xe9":
        if site[1:5] != rel_expect:
            print(f"FAIL site {S:#x} hooked elsewhere: {site.hex()}"); sys.exit(1)
        hooked = True
    else:
        if site != OLD:
            print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
        hooked = False

    off = SLOT - KTEXT
    cur = bytes(img[off:off + len(code)])
    if not all(b == 0xCC for b in cur) and cur != code:
        print(f"FAIL slot {SLOT:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)

    img[off:off + len(code)] = code
    if not hooked:
        off = S - KTEXT
        img[off:off + len(OLD)] = b"\xe9" + rel_expect + b"\x90" * (len(OLD) - 5)

    # static re-verify: hook decodes as jmp->slot, first stub insn = test rdi,rdi
    chk = [i for i in md.disasm(bytes(img[S - KTEXT:S - KTEXT + 8]), S)][:1]
    stub1 = [i for i in md.disasm(code, SLOT)][:1]
    assert chk and chk[0].mnemonic == "jmp" and int(chk[0].op_str, 16) == SLOT
    assert stub1 and stub1[0].mnemonic == "test" and "rdi" in stub1[0].op_str
    print(f"OK G42 [{g['tag']}] site {S:#x} -> slot {SLOT:#x} "
          f"(stub {len(code):#x}B, cont {g['cont']:#x})")

open(IMG, "wb").write(img)
h = hashlib.md5(bytes(img)).hexdigest()
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP24-G42: NULL-zone accessor family guard x5 — new md5 {h}")
