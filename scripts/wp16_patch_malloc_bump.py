#!/usr/bin/env python3
"""WP16 #10 v2 — systemic malloc bump at the NULL-return node
         (crash 0x9e9471ad CR2=0x8 W — malloc returned NULL).

ROOT CAUSE (GDB si-stepped):
  The LAPIC eventtimer registration mallocs its timer object:
  'malloc(0x60, ctx=0x9fec5bb0, 0x102)' -> the small path
  0x9eff8c12 -> WP13's cave11 guard: rbx = [ctx+0x18] (the malloc
  domain's zone-table) == NULL -> jumps straight to the designed
  malloc-NULL node 0x9eff8d32 ('xor r14d,r14d; test r12b,2; ... 0x9eff8d92
  mov rax,r14; ret') -> NULL -> the caller writes [NULL+8] -> panic.
  The zone tables were never initialized on this boot (the WP13
  family); WP13's guard returns NULL (correct for the callers that
  check), but callers that NEED the object crash.

FIX (v1 hooked 0x9eff8c46 — WRONG SPOT: the flow short-circuits at
  cave11 before it; v2 un-hooks that and hooks the NULL node itself):
  cave50 @0x9E401200 replacing [0x9eff8d32, 0x9eff8d39)
  ('xor r14d,r14d; test r12b,2', 7B):
    - bump-allocate the object: r14 = next; next += align16(size r14)
      state @DMAP(0x3F1A0830), window [0x3F1A1000, 0x3F200000) (380KB
      free: above the pcb seed page, below the arena pool; mapped,
      zeroed, writable DMAP memory — the caller's field writes
      initialize the object)
    - exhaustion -> replay the designed NULL ('xor r14d,r14d')
    - both paths replay 'test r12b,2' (the flags for the continuation
      jump at 0x9eff8d39) and return to it.
  EVERY malloc failure path (the NULL zone-table family, the large-alloc
  failure, the bucket-empty family) lands on this node — the bump
  answers them all with real memory.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE50 = 0x9E401200
S50, S50E = 0x9EFF8D32, 0x9EFF8D39          # xor r14d,r14d; test r12b,2 (7B)
BUMP_SLOT = 0xFFFF8E773F1A0830
WIN_LO = 0xFFFF8E773F1A1000
WIN_HI = 0x3F200000                         # low-32 compare bound

OLD50 = bytes.fromhex(
    "4531f6"          # xor r14d, r14d
    "41f6c402"        # test r12b, 2
)

C50 = f"""
    movabs r10, {BUMP_SLOT:#x}
    mov  rax, qword ptr [r10]
    test rax, rax
    jnz  bump_ok
    movabs rax, {WIN_LO:#x}
bump_ok:
    mov  r11, r14
    add  r11, 15
    and  r11, -16
    lea  r11, [rax + r11]
    cmp  r11d, {WIN_HI:#x}
    ja   no_mem
    mov  qword ptr [r10], r11
    mov  r14, rax
    test r12b, 2
    jmp  {0xFFFFFFFF9EFF8D39:#x}
no_mem:
    xor  r14d, r14d
    test r12b, 2
    jmp  {0xFFFFFFFF9EFF8D39:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C50, CAVE50)
print(f"cave50: {len(code):#x}B @ {CAVE50:#x}  hook {S50:#x} ({len(OLD50)}B)")
assert len(code) <= 0x80, "cave50 too big"

img = bytearray(open(IMG, "rb").read())

# --- [1] un-hook the v1 site 0x9eff8c46 if present (restore original) ---
V1_SITE = 0x9EFF8C46
V1_ORIG = bytes.fromhex("84c00fb64308")     # test al,al; movzx eax,[rbx+8]
off = V1_SITE - KTEXT
if bytes(img[off:off+5])[:1] == b"\xe9":
    img[off:off+len(V1_ORIG)] = V1_ORIG
    print(f"v1 site {V1_SITE:#x}: un-hooked (original restored)")

# --- [2] hook the NULL node ---
off = S50 - KTEXT
site = bytes(img[off:off+len(OLD50)])
if site[:1] == b"\xe9":
    rel_expect = CAVE50 - (S50 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S50:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S50:#x}: already hooked to cave50 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD50:
        print(f"FAIL site {S50:#x}: {site.hex()} (expected {OLD50.hex()})"); sys.exit(1)
    hooked = False

off = CAVE50 - KTEXT
cur = bytes(img[off:off+0x80])
if not all(b == 0xCC for b in cur):
    # v1 body present — blank and rewrite
    if cur[:5] == bytes.fromhex("483929") or b"\x48" == cur[:1]:
        img[off:off+0x80] = b"\xcc" * 0x80
        print(f"cave {CAVE50:#x}: v1 body found — blanking for rewrite")
    else:
        print(f"FAIL cave {CAVE50:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

md = Cs(CS_ARCH_X86, CS_MODE_64)
insns = list(md.disasm(code, CAVE50))
blob = code.hex()
if "49ba30081a3f778effff" not in blob:
    for i in insns:
        print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
    print("FAIL: bump-slot movabs not found"); sys.exit(1)

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE50 - (S50 + 5)
    off = S50 - KTEXT
    img[off:off+len(OLD50)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD50) - 5)

print("--- cave50 (v2) ---")
for i in insns:
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP16#10: systemic malloc bump at the NULL node (cave50 v2)")
