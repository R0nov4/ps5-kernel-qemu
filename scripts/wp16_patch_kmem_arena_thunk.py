#!/usr/bin/env python3
"""WP16 #15 — kmem-arena extend-thunk bootstrap (panic: failed to allocate waiting allocation).

ROOT CAUSE (GDB):
  The boot reached the SMP/ACPI stages ('ACPI APIC Table', 'FreeBSD/SMP:
  Multiprocessor System Detected: 0 CPUs', 'APIC: CPU 0 has ACPI ID 0')
  and allocates from the dynamically-created KMEM arena (the object at
  0xa1ab6f00, name 'kmem arena'): its extend callback slot
  [arena+0x428] is NULL (WP14's cave22 bootstrap only seeded the THREE
  static VM arenas) -> the alloc can't extend -> the WAIT path (the
  no-op sleep) retries -> 'panic: failed to allocate waiting allocation'.

FIX — cave57 @0x9E401580 replacing [0x9e9d7040, 0x9e9d7045)
  ('call 0x9ebe1950' — the wait-fail panic block head, 5B):
    1. bootstrap the arena: [r13+0x428] := the WP14 extend thunk
       0x9E65BF80 (the sanctioned thunk: 'jmp 0x9ebd7be0' -> 'jmp
       0x9E400000' -> cave22's pool serve — the arena-agnostic bump
       over the shared 14MB pool, 11MB still free) — every FUTURE alloc
       of this arena takes the real designed extend path.
    2. THIS allocation still fails: jump to the designed NOWAIT-fail
       return 0x9e9d7066 ('mov ebx,0xc; jmp 0x9e9d6ff6' — the error
       code 0xc) — the caller's fail path (the malloc NULL node ->
       cave50's bump) answers with real memory.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE57 = 0x9E401580
S57, S57E = 0x9E9D7040, 0x9E9D7045          # 'call 0x9ebe1950' (5B)
THUNK = 0xFFFFFFFF9E65BF80                  # the WP14 extend thunk

OLD57 = bytes.fromhex("e80ba92000")         # call 0xffffffff9ebe1950

C57 = f"""
    movabs rax, {THUNK:#x}
    mov  qword ptr [r13 + 0x428], rax
    jmp  {0xFFFFFFFF9E9D7066:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C57, CAVE57)
print(f"cave57: {len(code):#x}B @ {CAVE57:#x}  hook {S57:#x} ({len(OLD57)}B)")
assert len(code) <= 0x80, "cave57 too big"

img = bytearray(open(IMG, "rb").read())

off = S57 - KTEXT
site = bytes(img[off:off+len(OLD57)])
if site[:1] == b"\xe9":
    rel_expect = CAVE57 - (S57 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S57:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S57:#x}: already hooked to cave57 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD57:
        print(f"FAIL site {S57:#x}: {site.hex()} (expected {OLD57.hex()})"); sys.exit(1)
    hooked = False

off = CAVE57 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave {CAVE57:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

md = Cs(CS_ARCH_X86, CS_MODE_64)
insns = list(md.disasm(code, CAVE57))
blob = code.hex()
if "48b880bf659effffff" not in blob:
    for i in insns:
        print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
    print("FAIL: thunk movabs not found"); sys.exit(1)

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE57 - (S57 + 5)
    off = S57 - KTEXT
    img[off:off+len(OLD57)] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

print("--- cave57 ---")
for i in insns:
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP16#15: kmem-arena extend-thunk bootstrap (cave57)")
