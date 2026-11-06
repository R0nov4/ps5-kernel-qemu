#!/usr/bin/env python3
"""WP17 #3 — W1 v3: the vm_page supply extension (cave66 @0x9E401A00).

ROOT CAUSE (GDB wp17_gdb_c2 + the WP16#4/#5 forensics):
  With the kmem thunk fallback (WP17#2) the 0xF4000 large alloc now gets a
  fresh kernel-VA window — and the fill loop's populate part (0x9e8f3e90..)
  calls vm_page_alloc (0x9ef7a1a0) per 16KB page, whose supply IS the W1
  bump cave (hook @0x9EA05730 -> cave 0x9EE30100, WP9 + WP15#3):
    bump ptr @DMAP(0x3F000000), objects [0x3F010000,0x3F0F0000) step 0xF0,
    [obj+0x30] = the object's own seed-area offset (pmap_enter's phys
    read @0x9ecd27fb), exhaustion -> NULL.
  The 896KB region was fully consumed during vm_page_startup's 2GB walk
  (3823 objects) — every vm_page_alloc now returns NULL -> cave46's
  early-exit -> the fill returns the VA UNBACKED -> the caller's first
  write would page-fault.

FIX — W1 v3 (cave66; the WP15#3 rewrite pattern, relocated because v3
  no longer fits the 0x80 reservation):
  primary [0x3F010000,0x3F0F0000) step 0xF0 (unchanged);
  exhausted -> EXTENSION SLICES carved from the WP14 pool:
    ext-base slot @DMAP(0x3F1A0840), pool-next @DMAP(0x3F004008)
    (cave22's scratch +8), 1MB per slice, pool floor guard 0x3FF00000
    (leaves the top 1MB for the kmem extends themselves);
    a slice = [pool_next, pool_next+1MB): pool_next += 1MB (carved),
    ext_base := the slice, bump continues inside it step 0xF0.
    A fresh slice is carved ONLY when the bump walks past the current
    one — the pool drains by 1MB per ~6991 vm_page structs.
  The extension objects are pristine-zero DMAP pages (the trampoline's
  seed-area fill) whose own pages back them — identical semantics to the
  primary region ([obj+0x30] = the object's own offset).
  The old W1 v2 hook @0x9EA05730 is re-pointed to cave66; the v2 body
  at 0x9EE30100 becomes dead (blanked for cleanliness).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE66 = 0x9E401A00                          # W1 v3 (0x100B reservation)
W1_HOOK = 0x9EA05730                         # vm_page_alloc's W1 call site
OLD_W1_V2 = 0x9EE30100                       # the WP15#3 cave (dead after this)

BUMP_SLOT = 0xFFFF8E773F000000               # W1 bump ptr (DMAP)
W1_LO = 0x3F010000
W1_HI = 0x3F0F0000
EXT_BASE = 0xFFFF8E773F1A0840                # the current extension slice base
EXT_SIZE = 0x100000                          # 1MB per slice
POOL_NEXT = 0xFFFF8E773F004008               # cave22's pool-next scratch
POOL_FLOOR = 0x3FF00000                      # leave the top 1MB for kmem extends
POOL_DEFAULT = 0x3F770000                    # WP14's pool start (un-init fallback)
DMAP_BASE = 0xFFFF8E7700000000

# the current hook bytes: jmp 0x9EE30100 (from 0x9EA05730)
rel_v2 = OLD_W1_V2 - (W1_HOOK + 5)
OLD_HOOK = b"\xe9" + rel_v2.to_bytes(4, "little", signed=True)

W1V3 = f"""
    movabs rax, {BUMP_SLOT:#x}
    mov  rcx, qword ptr [rax]
    test rcx, rcx
    jnz  have
    mov  ecx, {W1_LO:#x}
have:
    cmp  ecx, {W1_HI:#x}
    jb   go
    movabs r10, {EXT_BASE:#x}
    mov  r11, qword ptr [r10]
    test r11, r11
    jz   carve
    lea  rdx, [r11 + {EXT_SIZE:#x}]
    cmp  rcx, rdx
    jb   go
carve:
    movabs r10, {POOL_NEXT:#x}
    mov  r11, qword ptr [r10]
    test r11, r11
    jnz  have_pool
    mov  r11d, {POOL_DEFAULT:#x}
have_pool:
    cmp  r11, {POOL_FLOOR:#x}
    jae  exhausted
    movabs r10, {EXT_BASE:#x}
    mov  qword ptr [r10], r11
    movabs r10, {POOL_NEXT:#x}
    lea  rdx, [r11 + {EXT_SIZE:#x}]
    mov  qword ptr [r10], rdx
    mov  rcx, r11
go:
    lea  r8, [rcx + 0xf0]
    mov  qword ptr [rax], r8
    movabs rdx, {DMAP_BASE:#x}
    add  rdx, rcx
    mov  qword ptr [rdx + 0x30], rcx
    mov  rax, rdx
    ret
exhausted:
    xor  eax, eax
    ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(W1V3, CAVE66)
print(f"cave66 (W1 v3): {len(code):#x}B @ {CAVE66:#x}")
assert len(code) <= 0x100, "W1 v3 overruns its 0x100 reservation"

img = bytearray(open(IMG, "rb").read())

# --- verify + re-point the W1 hook ---
off = W1_HOOK - KTEXT
cur = bytes(img[off:off+5])
rel_v3 = CAVE66 - (W1_HOOK + 5)
NEW_HOOK = b"\xe9" + rel_v3.to_bytes(4, "little", signed=True)
if cur == NEW_HOOK:
    print(f"W1 hook {W1_HOOK:#x}: already points to cave66 (idempotent rewrite)")
elif cur == OLD_HOOK:
    print(f"W1 hook {W1_HOOK:#x}: v2 target confirmed ({OLD_W1_V2:#x})")
else:
    print(f"FAIL W1 hook {W1_HOOK:#x}: {cur.hex()} (expected {OLD_HOOK.hex()})"); sys.exit(1)

# --- verify the v2 body is where we think (head bytes) before blanking ---
off2 = OLD_W1_V2 - KTEXT
v2_head = bytes(img[off2:off2+8])
V2_HEAD_KNOWN = bytes.fromhex("48b80000003f778effff")   # movabs rax, 0xffff8e773f000000
if v2_head == V2_HEAD_KNOWN or all(b == 0xCC for b in v2_head):
    print(f"W1 v2 body @ {OLD_W1_V2:#x}: found ({v2_head.hex()}) — blanking")
    img[off2:off2+0x80] = b"\xcc" * 0x80
else:
    print(f"WARN W1 v2 body unexpected ({v2_head.hex()}) — blanking anyway")
    img[off2:off2+0x80] = b"\xcc" * 0x80

# --- write cave66 ---
off = CAVE66 - KTEXT
img[off:off+len(code)] = code

# --- re-point the W1 hook @0x9EA05730 -> cave66 ---
off_hook = W1_HOOK - KTEXT
img[off_hook:off_hook+5] = NEW_HOOK

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave66 (W1 v3) ---")
for i in md.disasm(code, CAVE66):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP17#3: W1 v3 — vm_page supply extension (pool-carved 1MB slices)")
