#!/usr/bin/env python3
"""WP16 #13 — OID tree walk family guards (crash 0x9eef424c CR2=0x18 R).

ROOT CAUSE: the same NULL-terminator walk family as WP16#12 (cave52),
  three more instances inside the sysctl OID-tree code (0x9eef4xxx):
    0x9eef4210/0x9eef424c/0x9eef4380: 'mov r10,[rax+0x18]; test r10,r10'
  — the walk advances 'mov rax,[rax]' and dereferences [rax+0x18];
  the wiped static registration data terminates the list with NULL ->
  [0+0x18] -> CR2=0x18.

FIX: three caves (53/54/55), one per instance — rax == 0 -> jump to the
  shared walk-exit 0x9eef4395 (the designed continuation all three
  'duplicate found' paths take); rax != 0 -> replay the mov+test and
  return to the original branch.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

WALK_EXIT = 0xFFFFFFFF9EEF4395

SITES = [
    # (cave, site, span_end, back_addr)
    (0x9E401380, 0x9EEF4210, 0x9EEF4217, 0xFFFFFFFF9EEF4217),
    (0x9E401400, 0x9EEF424C, 0x9EEF4253, 0xFFFFFFFF9EEF4253),
    (0x9E401480, 0x9EEF4380, 0x9EEF4387, 0xFFFFFFFF9EEF4387),
]

OLD = bytes.fromhex("4c8b50184d85d2")      # mov r10,[rax+0x18]; test r10,r10 (7B)

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

caves = []
for cave, site, send, back in SITES:
    code = f"""
    test rax, rax
    jz   zero
    mov  r10, qword ptr [rax + 0x18]
    test r10, r10
    jmp  {back:#x}
zero:
    jmp  {WALK_EXIT:#x}
"""
    caves.append((cave, asm(code, cave), site, send))

for cave, code, site, send in caves:
    print(f"cave @ {cave:#x}: {len(code):#x}B  hook {site:#x} ({send-site}B)")
    assert len(code) <= 0x80

img = bytearray(open(IMG, "rb").read())

for cave, code, site, send in caves:
    off = site - KTEXT
    span = send - site
    site_bytes = bytes(img[off:off+span])
    if site_bytes[:1] == b"\xe9":
        rel_expect = cave - (site + 5)
        if site_bytes[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
            print(f"FAIL site {site:#x} hooked elsewhere"); sys.exit(1)
        print(f"site {site:#x}: already hooked (idempotent rewrite)")
        hooked = True
    else:
        if site_bytes != OLD:
            print(f"FAIL site {site:#x}: {site_bytes.hex()} != {OLD.hex()}"); sys.exit(1)
        hooked = False
    off = cave - KTEXT
    if not all(b == 0xCC for b in img[off:off+0x80]):
        print(f"FAIL cave {cave:#x} not pristine CC"); sys.exit(1)
    img[off:off+len(code)] = code
    if not hooked:
        rel = cave - (site + 5)
        off = site - KTEXT
        img[off:off+span] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (span - 5)

md = Cs(CS_ARCH_X86, CS_MODE_64)
for cave, code, site, send in caves:
    print(f"--- cave @ {cave:#x} (hook {site:#x}) ---")
    for i in md.disasm(code, cave):
        print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP16#13: OID tree walk family guards (caves 53/54/55)")
