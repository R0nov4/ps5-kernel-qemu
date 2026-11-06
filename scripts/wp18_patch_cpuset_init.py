#!/usr/bin/env python3
"""WP18 #2 — the cpuset-zone bootstrap NULL-skip (slot @0x9E401C80)
          (crash 0xffffffff9ec2d09c, CR2=0x0 WRITE).

ROLLBACK CONTEXT: this is the crash WP17 #11 'cave69' used to paper over by
  BUMPING the zone-import failure (making zone_create/bucket-alloc return
  raw pages in EARLY boot -> witness/early zones activated before
  'Preloaded elf kernel' -> the randompid GPF 0x9e8b7908 REGRESSION).
  That approach is BANNED in WP18: the allocators keep their designed
  NULL-on-failure semantics; the crash SITE gets a local guard instead.

ROOT CAUSE:
  The post-'APIC: CPU 0' SYSINIT cpuset bootstrap (fn 0x9ec2d040, called
  from the SYSINIT walker @0x9e9268f8):
    zone_create(0x9e82b0e0)("cpuset", 0x48, ...) -> [0xa1e71ea8]
    rax = bucket_alloc(0x9e82b880)(zone, 0, 0x102)   <- NULL (the import
                                                        never initialized)
    mov qword ptr [rax], -1          ; 0x9ec2d09c  <<< CR2 = 0 WRITE
    ... a 15-instruction object-init block ([rax+0x40]=0, the TAILQ link
    into the global list @0xa1e71ed0, [rax+0x28], [rax+8]=1, [rax+0xc]=1,
    the globals 0xa1e71ec8/0xa1e71eb8) ...
    rbx = bucket_alloc(...)          ; the 2nd object (would fail too)
    ... init(rbx, first, 1) ...      ; 0x9ec2cf60
    mov rax, rbx; epilogue           ; 0x9ec2d158 -> returns the root object
  The caller stores the result at [0xa19788c0] without a NULL check.

FIX — the LOCAL GUARD (the designed NULL flow, exactly like WP13's
  subsystem skips): hook the crash site [0x9ec2d09c, 0x9ec2d0a3) (7B
  'mov qword ptr [rax], -1'):
    rax == 0  -> the allocation failed: skip the WHOLE init block ->
                 xor ebx, ebx (the epilogue's 'mov rax,rbx' then returns
                 the designed NULL) -> jump the function's own epilogue
                 0x9ec2d158 (mov rax,rbx; add rsp,8; pop rbx; pop rbp;
                 ret — the frame is [rax-slot][rbx][rbp][ret] and is
                 balanced at that point);
    rax != 0  -> replay 'mov qword ptr [rax], -1' -> 0x9ec2d0a3 (the
                 designed init continues untouched).
  The zone/malloc machinery is NOT modified: it still returns NULL on
  failure; the bootstrap just tolerates its own NULL answer.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E401C80                    # the old cave69 slot, freed by the rollback
S, SEND = 0x9EC2D09C, 0x9EC2D0A3    # mov qword ptr [rax], -1 (7B)
CONT = 0xFFFFFFFF9EC2D0A3            # the designed init continues
EPILOG = 0xFFFFFFFF9EC2D158          # mov rax,rbx; add rsp,8; pop rbx; pop rbp; ret

OLD = bytes.fromhex("48c700ffffffff")   # mov qword ptr [rax], 0xffffffffffffffff

C = f"""
    test rax, rax
    jz   alloc_failed
    mov  qword ptr [rax], 0xffffffffffffffff
    jmp  {CONT:#x}
alloc_failed:
    xor  ebx, ebx
    jmp  {EPILOG:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C, SLOT)
print(f"slot 0x{SLOT:x}: {len(code):#x}B  hook {S:#x} (7B)")
assert len(code) <= 0x80

img = bytearray(open(IMG, "rb").read())

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
print("site + slot assertions OK")

img[off:off+len(code)] = code
if not hooked:
    rel = SLOT - (S + 5)
    off = S - KTEXT
    img[off:off+len(OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD) - 5)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cpuset-init NULL skip (slot 0x9E401C80) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#2: cpuset-zone bootstrap NULL-skip (local guard @0x9E401C80)")
