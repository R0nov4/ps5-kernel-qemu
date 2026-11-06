#!/usr/bin/env python3
"""WP17 #13 — the malloc zone-lookup validation (cave73; the jump-to-a-string
          crash IP=0x9f6f4b2f). The bucket-alloc entry NULL guard already
          exists as WP12's cave7 @0x9EE30900 (verified, reused).

ROOT CAUSE (GDB wp17_gdb_c14/c15):
  The malloc TYPE's zone-table ([ctx+0x18]) is a fresh ZERO bump page on
  this boot; the static class array @0xa0feb8d0 therefore answers the
  zone lookup with whatever pristine .data sits in the UNREGISTERED
  slot — for several size classes that is the static 'TSC-low' event
  timer object 0xa0fec510, whose hook fields are STRINGS:
    [+0x90]=0x9f728ef8  [+0x98]=0x9e6609e8  [+0xa0]=0x9f77dc47
    [+0xb0]=0x9f6f4b2f  (the 'import' the chunk allocator calls!)
  The bucket/chunk machinery then runs the designed validation (the
  thunk-table range checks), FAILS it, prints the warn — and calls the
  invalid pointer anyway -> IP = the string -> trap.

FIX (2 layers):
  A) cave73 @0x9E401E80 hooking the malloc's zone load
     [0x9eff8c6b, 0x9eff8c70) ('mov rbx,[rsi+rax*8]' + the '31' head of
     'xor esi,esi'): validate the loaded zone — its [+0xb0] (the import
     every allocator path uses) must be NULL or inside the THUNK REGION
     [0x9E650000, 0x9E660000) (all the validated hook tables —
     0x9e657140/0x9e6581d8/0x9e658cf0/0x9e658d18/0x9e65a700/0x9e65af68/
     0x9e65edb0/0x9e65bf80 — live there). A 'zone' whose import is a
     string/non-thunk is NOT a zone -> rbx := NULL -> the designed
     no-zone flow (the malloc NULL node -> cave50's bump).
  B) cave74 @0x9E401F00 hooking the bucket allocator's entry
     [0x9e82b880, 0x9e82b885) ('push rbp; mov rbp,rsp; 41'57'):
     rdi == 0 -> the designed NULL return (xor eax,eax; ret — nothing
     modified yet); else replay the prologue head -> 0x9e82b886.
"""
import sys
import struct
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE73 = 0x9E401E80
S73, S73E = 0x9EFF8C6B, 0x9EFF8C70          # mov rbx,[rsi+rax*8]; [31]f6 (5B)
CONT73 = 0xFFFFFFFF9EFF8C71                  # 'mov rdi,rbx' (after the replayed xor)

CAVE74 = 0x9E401F00
S74, S74E = 0x9E82B880, 0x9E82B885          # push rbp; mov rbp,rsp; [41]57 (5B)
CONT74 = 0xFFFFFFFF9E82B886                  # 'push r14' (the designed prologue tail)

THUNK_LO = 0xFFFFFFFF9E650000
THUNK_HI = 0xFFFFFFFF9E660000

OLD73 = bytes.fromhex("488b1cc631")          # mov rbx,[rsi+rax*8]; 31
OLD74 = bytes.fromhex("554889e541")          # push rbp; mov rbp,rsp; 41

C73 = f"""
    mov  rbx, qword ptr [rsi + rax*8]
    test rbx, rbx
    jz   ok
    test rbx, 0x7
    jnz  bad
    mov  rdx, rbx
    shr  rdx, 48
    cmp  edx, 0xffff
    jne  bad
    mov  rdx, qword ptr [rbx + 0xb0]
    test rdx, rdx
    jz   ok
    movabs r10, {THUNK_LO:#x}
    movabs r11, {THUNK_HI:#x}
    cmp  rdx, r10
    jb   bad
    cmp  rdx, r11
    jb   ok
bad:
    xor  ebx, ebx
ok:
    xor  esi, esi
    jmp  {CONT73:#x}
"""

C74 = f"""
    test rdi, rdi
    jz   nullret
    push rbp
    mov  rbp, rsp
    push r15
    jmp  {CONT74:#x}
nullret:
    xor  eax, eax
    ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code73 = asm(C73, CAVE73)
code74 = asm(C74, CAVE74)
print(f"cave73: {len(code73):#x}B @ {CAVE73:#x}  hook {S73:#x} (5B)")
print(f"cave74: {len(code74):#x}B @ {CAVE74:#x}  hook {S74:#x} (5B)")
assert len(code73) <= 0x80 and len(code74) <= 0x80

img = bytearray(open(IMG, "rb").read())

def install(cave, site, old, code):
    off = site - KTEXT
    cur = bytes(img[off:off+len(old)])
    if cur[:1] == b"\xe9":
        rel_expect = cave - (site + 5)
        if cur[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
            print(f"FAIL site {site:#x} hooked elsewhere: {cur[:5].hex()}"); sys.exit(1)
        print(f"site {site:#x}: already hooked -> {cave:#x} (idempotent rewrite)")
        hooked = True
    else:
        if cur != old:
            print(f"FAIL site {site:#x}: {cur.hex()} != {old.hex()}"); sys.exit(1)
        hooked = False
    off = cave - KTEXT
    curc = bytes(img[off:off+len(code)])
    if not all(b == 0xCC for b in curc) and curc != code:
        img[off:off+0x80] = b"\xcc" * 0x80
        print(f"cave {cave:#x}: stale body — blanking for rewrite")
    img[off:off+len(code)] = code
    if not hooked:
        rel = cave - (site + 5)
        off = site - KTEXT
        img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)
    print(f"site + cave {cave:#x} assertions OK")

install(CAVE73, S73, OLD73, code73)

# --- cave74 check: WP12's cave7 @0x9EE30900 already guards the bucket-alloc
#     entry with the exact same NULL-zone semantics (rdi==0 -> xor eax,eax;
#     ret) — verify it is in place and SKIP our redundant cave74.
off = S74 - KTEXT
cur74 = bytes(img[off:off+5])
rel74 = struct.unpack("<i", cur74[1:5])[0] if cur74[0] == 0xE9 else 0
tgt74 = (S74 + 5 + rel74) & 0xFFFFFFFF
if cur74[0] == 0xE9 and tgt74 == 0x9EE30900:
    print(f"site {S74:#x}: WP12 cave7 (0x9EE30900) already guards the entry — cave74 SKIPPED")
elif cur74 == OLD74:
    print(f"site {S74:#x}: pristine (cave7 should have hooked it — the build chain order!) — installing cave74")
    install(CAVE74, S74, OLD74, code74)
else:
    print(f"FAIL site {S74:#x} unexpected: {cur74.hex()}"); sys.exit(1)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave73 (zone-lookup validation) ---")
for i in md.disasm(code73, CAVE73):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
print("--- cave74 (bucket-alloc entry guard) ---")
for i in md.disasm(code74, CAVE74):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP17#13: zone-lookup validation + bucket-alloc entry guard (caves 73/74)")
