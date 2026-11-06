#!/usr/bin/env python3
"""WP16 #7 — region-manager constructor object bump (crash 0x9e6b6ef1 CR2=0x0 W).

ROOT CAUSE:
  kmem_suballoc's region alloc now SUCCEEDS (cave47's bump) -> the
  post-alloc constructor 0x9e6b6eb0 builds the sub-manager object:
  'mov rdi, [0xa1148590]' (the zone) -> 'call 0x9e82b880' (the object
  allocator — the WP13 'malloc->NULL' family: the zone's per-CPU buckets
  are WP12-wiped zeros) -> returns NULL -> 'mov [rax], rax' @0x9e6b6ef1
  writes the list-head self-link at NULL+0 -> panic.
  (WP13 guarded the callers that can SKIP the object; this caller NEEDS
  the object — it is the sub-manager being constructed.)

FIX — cave48 @0x9E401100 replacing [0x9e6b6ef1, 0x9e6b6ef8)
  ('mov [rax],rax; mov [rax+8],rax', 7B):
    - rax != 0: replay both stores, continue 0x9e6b6ef8 (the designed
      constructor — every later field write initializes the object)
    - rax == 0: bump-allocate a 0x400-byte object from
      DMAP [0x3F0F0000, 0x3F100000) (the 64KB free gap above the W1
      exhaustion bound — zero RAM, writable, never used by anything
      else; 64 objects), state slot @DMAP(0x3F1A0820) (pcb seed page
      +0x820 — free), then run the replayed stores on the fresh object.
      On exhaustion: return NULL via the constructor's own epilogue
      (add rsp,8; pop rbx/r14/r15/rbp; ret) — the caller's NULL check
      (0x9e8f3cda) takes the designed failure path.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE48 = 0x9E401100
S48, S48E = 0x9E6B6EF1, 0x9E6B6EF8          # mov [rax],rax; mov [rax+8],rax (7B)
BUMP_LO = 0xFFFF8E773F0F0000                # DMAP(0x3F0F0000)
BUMP_HI = 0x3F100000                        # low-32 compare bound
BUMP_SLOT = 0xFFFF8E773F1A0820              # state slot (pcb seed page +0x820)
OBJ_SIZE = 0x400

OLD48 = bytes.fromhex(
    "488900"          # mov qword ptr [rax], rax
    "48894008"        # mov qword ptr [rax + 8], rax
)

C48 = f"""
    test rax, rax
    jnz  have_obj
    movabs r10, {BUMP_SLOT:#x}
    mov  rax, qword ptr [r10]
    test rax, rax
    jnz  bump_ok
    movabs rax, {BUMP_LO:#x}
bump_ok:
    lea  r11, [rax + {OBJ_SIZE:#x}]
    cmp  r11d, {BUMP_HI:#x}
    ja   no_mem
    mov  qword ptr [r10], r11
have_obj:
    mov  qword ptr [rax], rax
    mov  qword ptr [rax + 8], rax
    jmp  {0xFFFFFFFF9E6B6EF8:#x}
no_mem:
    xor  eax, eax
    add  rsp, 8
    pop  rbx
    pop  r14
    pop  r15
    pop  rbp
    ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C48, CAVE48)
print(f"cave48: {len(code):#x}B @ {CAVE48:#x}  hook {S48:#x} ({len(OLD48)}B)")
assert len(code) <= 0x80, "cave48 too big"

img = bytearray(open(IMG, "rb").read())

off = S48 - KTEXT
site = bytes(img[off:off+len(OLD48)])
if site[:1] == b"\xe9":
    rel_expect = CAVE48 - (S48 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S48:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S48:#x}: already hooked to cave48 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD48:
        print(f"FAIL site {S48:#x}: {site.hex()} (expected {OLD48.hex()})"); sys.exit(1)
    hooked = False

off = CAVE48 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave {CAVE48:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

md = Cs(CS_ARCH_X86, CS_MODE_64)
insns = list(md.disasm(code, CAVE48))
blob = code.hex()
if "49ba20081a3f778effff" not in blob:
    for i in insns:
        print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
    print("FAIL: bump-slot movabs not found"); sys.exit(1)

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE48 - (S48 + 5)
    off = S48 - KTEXT
    img[off:off+len(OLD48)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD48) - 5)

print("--- cave48 ---")
for i in insns:
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP16#7: region-mgr constructor object bump (cave48)")
