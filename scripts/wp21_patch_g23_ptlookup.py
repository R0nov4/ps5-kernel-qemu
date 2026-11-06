#!/usr/bin/env python3
"""WP21 G23 — THE SELF-MAP PT/PV LOOKUP GUARDS (the 0xa1978730 twins)
          (a known crash between done=1006 and 'Device configuration
           finished.' — the user's cheat sheet: 'self-map PT lookup and
            phys->pv lookup (incl. 0x9e92811d with CR2=0x200)')

ROOT CAUSE: the lookup pair at 0x9e928110 / 0x9e928190 both dereference
the shared map/pmap global [0xa1978730] without a NULL check:

      0x9e928110:  rax = [0xa1978730]; rax = [rax + 0x200]   <<< CR2=0x200
      0x9e928190:  rax = [0xa1978730]; rbx = [rax + 0x10]    <<< CR2=0x10

On our boot the global can still hold the designed NULL (cold state)
when the deep-march stages call the pair, so the lookup faults on the
+offset deref before any caller can react.

FIX — THE LOCAL GUARD (the designed not-present/zero answer): hook both
entries — global NULL -> answer 0 immediately (the 'nothing to report'
value both fns produce on their empty path); global live -> replay the
prologue and run the original lookup. One family, two twins.
Slots 0x9E403E00 + 0x9E403E80.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./wp21_kit/wp3_boot/kernel_raw.bin"

GLOB = 0xFFFFFFFFA1978730
PAIR = [
    (0x9E928110, 0x9E403E00, 0xFFFFFFFF9E928115, "self-map PT lookup"),
    (0x9E928190, 0x9E403E80, 0xFFFFFFFF9E928195, "phys->pv lookup"),
]
OLD = bytes.fromhex("554889e553")     # push rbp; mov rbp,rsp; push rbx (5B)

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

for S, SLOT, CONT, NAME in PAIR:
    C = f"""
        movabs r10, {GLOB:#x}
        mov    r10, qword ptr [r10]
        test   r10, r10
        jnz    real
        xor    eax, eax
        ret
    real:
        push   rbp
        mov    rbp, rsp
        push   rbx
        jmp    {CONT:#x}
    """
    code = asm(C, SLOT)
    assert len(code) <= 0x80, f"slot code too big: {len(code):#x}"

    off = S - KTEXT
    site = bytes(img[off:off+len(OLD)])
    if site[:1] == b"\xe9":
        rel_expect = SLOT - (S + 5)
        if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
            print(f"FAIL site {S:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
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

    print(f"OK WP21-G23 twin {NAME}: NULL-global guard @0x{S:X} "
          f"(slot 0x{SLOT:X}) — the designed zero answer")
    for i in md.disasm(code, SLOT):
        print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print("OK WP21-G23: both lookup twins guarded")
