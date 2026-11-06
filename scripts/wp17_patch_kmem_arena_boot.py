#!/usr/bin/env python3
"""WP17 #6 — the kmem-arena bootstrap (cave67 @0x9E401B00, lazy one-shot).

ROOT CAUSE (GDB wp17_gdb_c4 + the grow-helper dissection):
  The 0xF4000 (1MB hash-table) kmem alloc's slow path needs an extent NODE
  from the arena's free-node cache [arena+0x408]; the kmem arena
  0xffffffffa1ab6f00 NEVER got WP14's cave22 bootstrap (cave22 only treats
  the 3 STATIC VM arenas) — its node cache = NULL, grow-counter +0x410 = 0.
  The grow helper (0x9e9d7090) then tries the extent-node ZONE
  [0xa1ab8440] (never created on this boot — the WP13 zone family) via the
  zone-bucket allocator 0x9e82b880 -> NULL -> the wait-fail -> (with
  WP17#5) a clean 0xc error -> the 1MB allocs all fail.

FIX — the same treatment cave22 gives the 3 static arenas, applied lazily
  to ANY arena entering the kmem allocator with an empty bootstrap:
  hook [0x9e9d6730, 0x9e9d6735) (the kmem fn entry 'push rbp; mov rbp,rsp;
  41'56'):
    [rdi+0x410] != 0  -> bootstrapped already -> replay the prologue
    else:
      - carve 64KB from the WP14 pool (pool-next @DMAP(0x3F004008), floor
        guard 0x3FF00000) — the W1-v3 carve pattern
      - build the 1024-node chain (cave22's exact list format:
        node+0x10 = next, node+0x18 = &(prev.next), head anchor at
        [arena+0x408], node0.prev = arena+0x408)
      - [arena+0x410] := 0x40000 (suppresses the dead grow loop — the
        helper's early return 0x9e9d718d)
      - [arena+0x3d0] := arena+0x3d0 (the empty extent-list self-anchor)
      - [arena+0x3d8] := DMAP(0x3F130000) (the free slot in the hash
        arrays region [0x3F100000,0x3F140000))
      - [arena+0x428] := the WP14 thunk (belt & braces — cave65 also
        substitutes at the read)
      - zap the order buckets [arena+0xf8, arena+0x2d8) (60 qwords —
        live-residue safety, the cave22 zap)
    replay 'push rbp; mov rbp,rsp; push r14' -> 0x9e9d6736 (push rbx...)
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE67 = 0x9E401B00
S67, S67E = 0x9E9D6730, 0x9E9D6735          # push rbp; mov rbp,rsp; [41]56 (5B)
CONT67 = 0xFFFFFFFF9E9D6736                  # 'push rbx' (the designed prologue tail)

POOL_NEXT = 0xFFFF8E773F004008               # cave22's pool-next scratch
POOL_DEFAULT = 0x3F770000
POOL_FLOOR = 0x3FF00000
CHAIN_BYTES = 0x10000                        # 64KB = 1024 nodes x 0x40
DMAP_BASE = 0xFFFF8E7700000000
HASH_SLOT = 0xFFFF8E773F130000               # the free hash-array slot
THUNK = 0xFFFFFFFF9E65BF80

OLD67 = bytes.fromhex("554889e541")          # push rbp; mov rbp,rsp; 41

C67 = f"""
    mov  eax, dword ptr [rdi + 0x410]
    test eax, eax
    jnz  boot_done
    movabs r10, {POOL_NEXT:#x}
    mov  r11, qword ptr [r10]
    test r11, r11
    jnz  have_pool
    mov  r11d, {POOL_DEFAULT:#x}
have_pool:
    movabs r12, {POOL_FLOOR:#x}
    cmp  r11, r12
    jae  boot_done
    lea  rdx, [r11 + {CHAIN_BYTES:#x}]
    mov  qword ptr [r10], rdx
    movabs r10, {DMAP_BASE:#x}
    mov  rax, r10
    add  rax, r11
    mov  qword ptr [rdi + 0x408], rax
    lea  rdx, [rdi + 0x408]
    mov  qword ptr [rax + 0x18], rdx
    mov  ecx, 1023
chain:
    lea  rdx, [rax + 0x40]
    mov  qword ptr [rax + 0x10], rdx
    lea  rdx, [rax + 0x10]
    add  rax, 0x40
    mov  qword ptr [rax + 0x18], rdx
    dec  ecx
    jnz  chain
    mov  dword ptr [rdi + 0x410], 0x40000
    lea  rdx, [rdi + 0x3d0]
    mov  qword ptr [rdi + 0x3d0], rdx
    movabs rdx, {HASH_SLOT:#x}
    mov  qword ptr [rdi + 0x3d8], rdx
    movabs rdx, {THUNK:#x}
    mov  qword ptr [rdi + 0x428], rdx
    lea  rdx, [rdi + 0xf8]
    xor  eax, eax
    mov  ecx, 60
zap:
    mov  qword ptr [rdx], rax
    add  rdx, 8
    dec  ecx
    jnz  zap
boot_done:
    push rbp
    mov  rbp, rsp
    push r14
    jmp  {CONT67:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C67, CAVE67)
print(f"cave67: {len(code):#x}B @ {CAVE67:#x}  hook {S67:#x} (5B)")
assert len(code) <= 0x100, "cave67 overruns its 0x100 reservation"

img = bytearray(open(IMG, "rb").read())

off = S67 - KTEXT
site = bytes(img[off:off+len(OLD67)])
if site[:1] == b"\xe9":
    rel_expect = CAVE67 - (S67 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S67:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S67:#x}: already hooked to cave67 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD67:
        print(f"FAIL site {S67:#x}: {site.hex()} != {OLD67.hex()}"); sys.exit(1)
    hooked = False

off = CAVE67 - KTEXT
cur = bytes(img[off:off+len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    print(f"FAIL cave {CAVE67:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)
print("site + cave assertions OK")

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE67 - (S67 + 5)
    off = S67 - KTEXT
    img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave67 (kmem-arena bootstrap) ---")
for i in md.disasm(code, CAVE67):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP17#6: kmem-arena lazy bootstrap (cave67)")
