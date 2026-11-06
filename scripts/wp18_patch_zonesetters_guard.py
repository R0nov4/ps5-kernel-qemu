#!/usr/bin/env python3
"""WP18 #12 — the zone-setter family NULL-zone guard x4
          (crash 0xffffffff9e82d2ca, CR2=0x40; + the 3 siblings).

The SYSINIT zone-setup family calls the zone 'limit setter' helpers with
  the zone_create result (NULL on this boot):
    fn 0x9e82d2c0: push rbp; push r14; push rbx; mov r14,rdi;
                   0x9e82d2ca  mov rdi,[rdi+0x40]   ; the zone's lock
                   0x9e82d2ce  mov rbx,rsi          ; the value
                   ... mtx_lock; [r14+0x138]=rbx; mtx_unlock(tail) ...
    fn 0x9e82d300: the same shape (0x9e82d30a / mov rbx,rsi @0x9e82d30e)
    fn 0x9e82d350: 5-push frame (0x9e82d35d / xor r15d,r15d @0x9e82d361)
    fn 0x9e82e010: the same shape (0x9e82e01a / xor esi,esi @0x9e82e01e)
  With rdi (the zone) == NULL the lock load faults (CR2=0x40).

FIX — the LOCAL GUARD on all four entry loads: NULL zone -> the plain
  replicated epilogue (the setters are pure no-ops without a zone);
  non-NULL -> replay the displaced instructions -> the designed flow.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

GUARDS = [
    # (slot, site, old, replay, cont, null-exit pops)
    (0x9E402280, 0x9E82D2CA, "488b7f404889f3",
     "mov rdi, qword ptr [rdi + 0x40]\nmov rbx, rsi",
     0xFFFFFFFF9E82D2D1, "pop rbx\npop r14\npop rbp\nret"),
    (0x9E402300, 0x9E82D30A, "488b7f404889f3",
     "mov rdi, qword ptr [rdi + 0x40]\nmov rbx, rsi",
     0xFFFFFFFF9E82D311, "pop rbx\npop r14\npop rbp\nret"),
    (0x9E402380, 0x9E82D35D, "488b7f404531ff",
     "mov rdi, qword ptr [rdi + 0x40]\nxor r15d, r15d",
     0xFFFFFFFF9E82D364, "pop rax\npop rbx\npop r14\npop r15\npop rbp\nret"),
    (0x9E402400, 0x9E82E01A, "488b7f4031f6",
     "mov rdi, qword ptr [rdi + 0x40]\nxor esi, esi",
     0xFFFFFFFF9E82E020, "pop rbx\npop r14\npop rbp\nret"),
]

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

for SLOT, S, OLDH, REPLAY, CONT, EXIT in GUARDS:
    OLD = bytes.fromhex(OLDH)
    C = f"""
        test rdi, rdi
        jz   nullzone
        {REPLAY}
        jmp  {CONT:#x}
    nullzone:
        {EXIT}
    """
    code = asm(C, SLOT)
    print(f"=== slot 0x{SLOT:x}: {len(code):#x}B  hook {S:#x} ({len(OLD)}B) ===")
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
        img[off:off+len(OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD) - 5)
    for i in md.disasm(code, SLOT):
        print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
    print("site + slot assertions OK")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#12: zone-setter family NULL-zone guard x4 (slots 0x9E402280..0x9E402400)")
