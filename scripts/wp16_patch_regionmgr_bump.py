#!/usr/bin/env python3
"""WP16 #6 — region-manager bump allocator (panic: kmem_suballoc: bad status return of 3).

ROOT CAUSE (GDB + the WP14 worklog's own analysis of the sibling path):
  vm_page_startup's tail calls kmem_suballoc(parent=kernel_map) ->
  the map's manager ([map+0x1d8] = the WP12-wiped kernel region manager,
  re-seeded to the ZERO page DMAP(0x3F00D000)) -> the region-manager
  alloc wrapper 0x9e6bb1b0 -> the inner best-fit walk 0x9e6ba9f0 over the
  manager's free lists ([mgr+0x1a8] = 0) -> fails -> returns 0xc ->
  'panic: kmem_suballoc: bad status return of 3'.
  (The WP14 arena bootstrap fixed the THREE VM arenas' extend callbacks —
  this is the REGION MANAGER itself, a different consumer.)

FIX (the WP14 cave22 bump pattern, applied to the region manager):
  cave47 @0x9E401080 replacing the wrapper's entry
  [0x9e6bb1b0, 0x9e6bb1bc) (12B: push rbp; mov rbp,rsp; push r14; push
  rbx; mov eax,[rbp+0x10]):
    - a REAL manager ([rdi+0x1a8] != 0, rdi != 0): replay the prologue,
      continue 0x9e6bb1bc (the designed path, untouched)
    - the ZERO-page manager ([rdi+0x1a8] == 0): hand out a fresh kernel-VA
      bump window:
        *out (rcx) := next;  next += align16k(size=r8)
        state slot @DMAP(0x3F1A0810) (the pcb-seed page +0x810 — free)
        window [0xffffffffa4000000, 0xffffffffa8000000) — 1GB of unused
        kernel VA above the image ([0x9e3f0000, 0xa06b0000)); the kmem
        consumers map it in later via pmap_enter
        return 0 (the designed success code)
        exhaustion (next > 0xa8000000) -> return 0xc (the designed
        failure code)
      The kmem submaps get a working VA range and the malloc-arena
      SYSINIT stage proceeds.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE47 = 0x9E401080
S47, S47E = 0x9E6BB1B0, 0x9E6BB1BC          # wrapper entry (12B)
BUMP_SLOT = 0xFFFF8E773F1A0810              # the bump-state slot (pcb seed page +0x810)
WIN_LO = 0xFFFFFFFFA4000000                # the VA window base
WIN_HI = 0xFFFFFFFFA8000000                # the VA window bound

OLD47 = bytes.fromhex(
    "55"              # push rbp
    "4889e5"          # mov rbp, rsp
    "4156"            # push r14
    "53"              # push rbx
    "8b4510"          # mov eax, dword ptr [rbp+0x10]
)

C47 = f"""
    test rdi, rdi
    jz   orig
    cmp  qword ptr [rdi + 0x1a8], 0
    jne  orig
    movabs r10, {BUMP_SLOT:#x}
    mov  rax, qword ptr [r10]
    test rax, rax
    jnz  have
    movabs rax, {WIN_LO:#x}
have:
    lea  r11, [r8 + 0x3fff]
    and  r11, -16384
    add  r11, rax
    cmp  r11, {WIN_HI:#x}
    ja   exhausted
    mov  qword ptr [r10], r11
    mov  qword ptr [rcx], rax
    xor  eax, eax
    ret
exhausted:
    mov  eax, 0xc
    ret
orig:
    push rbp
    mov  rbp, rsp
    push r14
    push rbx
    mov  eax, dword ptr [rbp + 0x10]
    jmp  {0xFFFFFFFF9E6BB1BC:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C47, CAVE47)
print(f"cave47: {len(code):#x}B @ {CAVE47:#x}  hook {S47:#x} ({len(OLD47)}B)")
assert len(code) <= 0x80, "cave47 too big"

img = bytearray(open(IMG, "rb").read())

off = S47 - KTEXT
site = bytes(img[off:off+len(OLD47)])
if site[:1] == b"\xe9":
    rel_expect = CAVE47 - (S47 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S47:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S47:#x}: already hooked to cave47 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD47:
        print(f"FAIL site {S47:#x}: {site.hex()} (expected {OLD47.hex()})"); sys.exit(1)
    hooked = False

off = CAVE47 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave {CAVE47:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

md = Cs(CS_ARCH_X86, CS_MODE_64)
insns = list(md.disasm(code, CAVE47))
blob = code.hex()
if "49ba10081a3f778effff" not in blob:
    for i in insns:
        print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
    print("FAIL: bump-slot movabs not found"); sys.exit(1)

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE47 - (S47 + 5)
    off = S47 - KTEXT
    img[off:off+len(OLD47)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD47) - 5)

print("--- cave47 ---")
for i in insns:
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP16#6: region-manager bump allocator (cave47)")
