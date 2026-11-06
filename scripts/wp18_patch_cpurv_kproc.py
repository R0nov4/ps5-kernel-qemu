#!/usr/bin/env python3
"""WP18 #10 — the cpurv_init kproc tolerance x2 (slots @0x9E402100 + 0x9E402180)
          (panic 'cpurv_init: kproc_create error 12').

The cpurv (CPU-reservation) SYSINIT creates TWO kprocs via 0x9ed162d0:
    0x9e798625  call 0x9ed162d0 ; add rsp,0x10 ; test eax,eax
    0x9e798630  jne 0x9e7987c6   -> panic (string @0x9e7987dc)
    0x9e7986cd  call 0x9ed162d0 ; add rsp,0x10 ; test eax,eax
    0x9e7986d8  jne 0x9e7987ea   -> panic (string @0x9e798800)
  Success epilogue 0x9e7987bb: 'add rsp,0x28; pop rbx; pop r14; pop r15;
  pop rbp; ret' (canary at 0x9e7987b2 reads r15 — replicated epilogue
  used instead, the frame is intact).

FIX — the LOCAL GUARD (the WP18 kproc-tolerance pattern) on BOTH call
  sites: replay the call; eax != 0 -> tolerate: xor eax,eax; 'add
  rsp,0x10' (discard the arg stack) + the replicated epilogue -> ret.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

KPROC = 0xFFFFFFFF9ED162D0

GUARDS = [
    # (slot, site, old-bytes, cont-after-call)
    (0x9E402100, 0x9E798625, "e8a6dc5700", 0xFFFFFFFF9E79862A),   # call #1
    (0x9E402180, 0x9E7986CD, "e8fedb5700", 0xFFFFFFFF9E7986D2),   # call #2
]

C = """
    call {KPROC:#x}
    test eax, eax
    jz   ok
    xor  eax, eax
    add  rsp, 0x10
    add  rsp, 0x28
    pop  rbx
    pop  r14
    pop  r15
    pop  rbp
    ret
ok:
    jmp  {CONT:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

img = bytearray(open(IMG, "rb").read())
md = Cs(CS_ARCH_X86, CS_MODE_64)

for SLOT, S, OLDH, CONT in GUARDS:
    OLD = bytes.fromhex(OLDH)
    code = asm(C.format(KPROC=KPROC, CONT=CONT), SLOT)
    print(f"=== slot 0x{SLOT:x}: {len(code):#x}B  hook {S:#x} (5B) ===")
    assert len(code) <= 0x80

    off = S - KTEXT
    site = bytes(img[off:off+len(OLD)])
    if site[:1] == b"\xe9":
        rel_expect = SLOT - (S + 5)
        if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
            print(f"FAIL site {S:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
        print(f"site {S:#x}: already hooked to slot {SLOT:#x} (idempotent rewrite)")
        hooked = True
    else:
        if site != OLD:
            print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
        hooked = False

    off = SLOT - KTEXT
    cur = bytes(img[off:off+len(code)])
    if not all(b == 0xCC for b in cur) and cur != code:
        print(f"FAIL slot {SLOT:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)

    img[off:off+len(code)] = code
    if not hooked:
        rel = SLOT - (S + 5)
        off = S - KTEXT
        img[off:off+len(OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True)
    for i in md.disasm(code, SLOT):
        print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
    print("site + slot assertions OK")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#10: cpurv_init kproc tolerance x2 (local guards @0x9E402100/0x9E402180)")
