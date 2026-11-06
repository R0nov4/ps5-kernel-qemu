#!/usr/bin/env python3
"""WP14 — arena bootstrap + fake extend callback + sleepq_add guard + sleep fail-safe.

USER ROOT CAUSE (verified by GDB on the live crash + full disasm):
  Crash 0x9f00a2e9 (CR2=0x28 WRITE, proc0/SceSwapper) is sleepq_add()
  [subr_sleepqueue.c, string 'sleepq_add' @0x9f683770, file string
  'W:/Build/J03950001/sys/freebsd/sys/kern/subr_sleepqueue.c' @0x9f6d5a7b]:
    0x9f00a240 sleepq_add(wchan=arena+0x40, lock=0xa1ab6800, wmesg="kernel arena",
                          flags=1, queue=0)
    branch 2 (bucket empty): r15 = curthread->td_sleepqueue [rbx+0x70] = NULL
    0x9f00a2e9  mov [r15+0x28], 0        ; <<< CRASH (r15=0)
  td_sleepqueue is NULL because the live dump captured thread0 MID-SLEEP
  ("swprsus" residue in td_wchan/td_wmesg): its sleepqueue was checked into
  the sleepqueue-chain hash (wiped residue) => NULL on our cold boot.

WHY the thread sleeps: the boot reached vm_page_startup (0x9ebd78c0 — the
panics 'startup: no room for tables' / 'startup: table size inconsistency'
are in it). It allocates the VM tables from the "kernel arena"
(0xa1ab6800 = [0x9fed8b10]). The arena is empty on cold boot:
  - the retry loop locks the arena, scan finds nothing, then calls the
    EXTEND callback [arena+0x428] = thunk 0x9e65bf80 -> 0x9ebd7be0
  - the callback allocates from the global region manager [0xa1950ab8]
    (already seeded by WP12 to DMAP(0x3F00D000), fresh-zero => EMPTY)
  - region alloc fails => callback returns 0xc => [arena+0x3e8]==0 &&
    [arena+0x440]==0 => msleep("kernel arena", timo=-1 = infinite) =>
    sleepq_add => CRASH.
  Arena internals that would ALSO crash on a successful extend:
  - [arena+0x408] node cache = 0 (wiped)  => 0x9e9d803e NULL deref
  - [arena+0x3d0] extent list = 0 (wiped) => 0x9e9d79d3 NULL write
  - order buckets [+0xf8..+0x2d8) have live-dump residue pointers
    (order 38 -> DMAP phys 1.87GB = UNMAPPED)

FIX WP14-A (primary — arena bootstrap + fake extend):
  cave22 @0x9E400000 (big 0xCC int3 island at the start of .text — verified
  653KB of 0xCC, no patches.inc entry below 0x9e642c5d):
    lazy one-time init (first call):
      - node chains 1024 x 0x40B for kernel/buffer/transient arenas
        (kernel @DMAP(0x3F740000), buffer @DMAP(0x3F750000),
         transient @DMAP(0x3F760000); above the WP9 W1 bump area 0x3F010000+)
      - [arena+0x410] node count := 0x40000 (suppresses the dead grow loop)
      - zero order buckets [arena+0xf8..+0x2d8)
      - [arena+0x3d0] := arena+0x3d0 (empty extent-list self-anchor)
      - [arena+0x428] := thunk 0x9e65bf80 (all 3 arenas extend via the cave)
      - pool next := DMAP(0x3F770000)
    serve: *out = next; next = min(next+align16k(size), DMAP(0x40000000));
           return 0 (0xc when exhausted)
    scratch (RW, not .text!): DMAP(0x3F004000) {+0 init, +8 next} — the
    user-suggested free seed page ([0x3F004000,0x3F009000) free & zero).
  thunk @0x9E65BF80: 'jmp 0x9ebd7be0' -> 'jmp 0x9E400000' (cave22)

FIX WP14-B (user-specified — sleepq_add td_sleepqueue guard):
  cave23 @0x9E400400:
    [gs:0]->td_sleepqueue != 0 -> replay prologue (push rbp; mov rbp,rsp;
      push r15) and continue at 0x9f00a246
    == 0 -> designed void exit replicated: rdi = td->td_lock+0x18,
      (rsi,rdx,rcx)=0, tail-jmp 0x9e8b7520 (the release the original
      epilogue tail-calls; the on-stack return address makes it return
      straight to sleepq_add's caller)
  entry hook @0x9F00A240: '55 48 89 e5 41' -> jmp cave23

FIX WP14-C (safety net — arena sleep -> designed error):
  @0x9E9D6C26: 'jne 0x9e9d7066' -> 'jmp' (0f85->e9 + nop): the sleep block
  (reached when the extend fails and [0x3e8]==0 && [0x440]==0) always takes
  the designed error exit 0xc: unlock + canary + 'mov eax,ebx(0xc)' + ret.
  Caller chain returns NULL => vm_page_startup panics with the CANONICAL
  FreeBSD 'panic: startup: no room for tables' instead of an infinite sleep.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE22 = 0x9E400000           # fake extend + arena bootstrap
CAVE23 = 0x9E400400           # sleepq_add guard
THUNK  = 0x9E65BF80           # arena extend thunk #0
SQENTRY = 0x9F00A240          # sleepq_add entry
FLIP   = 0x9E9D6C26           # arena sleep-block jne -> jmp
TAILREL = 0x9E8B7520          # sleepq_add designed tail-release target

# full 64-bit kernel VAs (the short constants above are for file offsets)
CAVE22_F  = 0xFFFFFFFF9E400000
THUNK_F   = 0xFFFFFFFF9E65BF80
TAILREL_F = 0xFFFFFFFF9E8B7520
SQCONT_F  = 0xFFFFFFFF9F00A246   # sleepq_add continuation (after replayed prologue)

SCRATCH   = 0xFFFF8E773F004000    # DMAP(0x3F004000): +0 init, +8 next
POOL_LO  = 0xFFFF8E773F200000    # DMAP(0x3F200000) — extent pool (14MB)
POOL_HI  = 0xFFFF8E7740000000    # DMAP(0x40000000) — 1GB DMAP top
ADV_CAP  = 0x100000              # max pool advance per extend (1MB)
HASH_K   = 0xFFFF8E773F100000    # kernel arena chunk-hash array (0x800 entries = 16KB)
HASH_B   = 0xFFFF8E773F110000    # buffer arena chunk-hash (0x100 entries = 2KB)
HASH_T   = 0xFFFF8E773F120000    # transient arena chunk-hash
NODES_K  = 0xFFFF8E773F140000    # kernel arena node chain
NODES_B  = 0xFFFF8E773F150000    # buffer arena
NODES_T  = 0xFFFF8E773F160000    # transient arena

THUNK_OLD  = bytes.fromhex("e95bbc5700")           # jmp 0x9ebd7be0
SQ_OLD     = bytes.fromhex("554889e541")           # push rbp; mov rbp,rsp; 41
FLIP_OLD   = bytes.fromhex("0f853a040000")         # jne 0x9e9d7066

# ---------------------------------------------------------------- cave22 asm
CAVE22_ASM = f"""
    push rcx
    mov  rax, qword ptr [{SCRATCH:#x}]
    test rax, rax
    jnz  serve_pop
    mov  rax, 1
    mov  qword ptr [{SCRATCH:#x}], rax
    movabs r8, {CAVE22_F + 0x2c0:#x}
    mov  r9d, 3
arena_loop:
    mov  r10, qword ptr [r8]
    mov  r11, qword ptr [r8 + 8]
    mov  rax, qword ptr [r8 + 16]
    mov  qword ptr [r10 + 0x3d8], rax
    mov  qword ptr [r10 + 0x408], r11
    lea  rax, [r10 + 0x408]
    mov  qword ptr [r11 + 0x18], rax
    mov  rax, r11
    mov  ecx, 1023
chain_loop:
    lea  rdx, [rax + 0x40]
    mov  qword ptr [rax + 0x10], rdx
    lea  rdx, [rax + 0x10]
    add  rax, 0x40
    mov  qword ptr [rax + 0x18], rdx
    dec  ecx
    jnz  chain_loop
    mov  dword ptr [r10 + 0x410], 0x40000
    lea  rdx, [r10 + 0xf8]
    xor  eax, eax
    mov  ecx, 60
zap_loop:
    mov  qword ptr [rdx], rax
    add  rdx, 8
    dec  ecx
    jnz  zap_loop
    lea  rax, [r10 + 0x3d0]
    mov  qword ptr [r10 + 0x3d0], rax
    movabs rax, {THUNK_F:#x}
    mov  qword ptr [r10 + 0x428], rax
    add  r8, 24
    dec  r9d
    jnz  arena_loop
    movabs rax, {POOL_LO:#x}
    mov  qword ptr [{SCRATCH + 8:#x}], rax
serve_pop:
    pop  rcx
serve:
    mov  rax, qword ptr [{SCRATCH + 8:#x}]
    movabs r10, {POOL_HI:#x}
    cmp  rax, r10
    jae  fail
    mov  qword ptr [rcx], rax
    lea  rdx, [rsi + 0x3fff]
    and  rdx, 0xffffffffffffc000
    movabs r11, {ADV_CAP:#x}
    cmp  rdx, r11
    jbe  adv_ok
    mov  rdx, r11
adv_ok:
    add  rax, rdx
    cmp  rax, r10
    jbe  store_next
    movabs rax, {POOL_HI:#x}
store_next:
    mov  qword ptr [{SCRATCH + 8:#x}], rax
    xor  eax, eax
    ret
fail:
    mov  eax, 0xc
    ret
"""

# ---------------------------------------------------------------- cave23 asm
CAVE23_ASM = f"""
    mov  rax, qword ptr gs:[0]
    cmp  qword ptr [rax + 0x70], 0
    jne  normal
    mov  rdi, qword ptr [rax]
    add  rdi, 0x18
    xor  esi, esi
    xor  edx, edx
    xor  ecx, ecx
    movabs r11, {TAILREL_F:#x}
    jmp  r11
normal:
    push rbp
    mov  rbp, rsp
    push r15
    movabs r11, {SQCONT_F:#x}
    jmp  r11
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print("ASM FAILED"); sys.exit(1)
    return bytes(enc)

cave22 = asm(CAVE22_ASM, CAVE22)
cave23 = asm(CAVE23_ASM, CAVE23)
print(f"cave22: {len(cave22):#x}B @ {CAVE22:#x}   cave23: {len(cave23):#x}B @ {CAVE23:#x}")
assert len(cave22) <= 0x2c0 and len(cave23) <= 0x100

# arena table appended after cave22 code: (arena, nodes, chunk-hash) triples
table = b"".join(int(v).to_bytes(8, "little") for v in
                 (0xFFFFFFFFA1AB6800, NODES_K, HASH_K,
                  0xFFFFFFFFA1AB7600, NODES_B, HASH_B,
                  0xFFFFFFFFA1AB7D00, NODES_T, HASH_T))
tbl_off = CAVE22 + 0x2c0
assert CAVE22 + len(cave22) <= tbl_off, "cave22 overlaps its table"

img = bytearray(open(IMG, "rb").read())

def chk(va, old, ln=None):
    off = va - KTEXT
    ln = ln or len(old)
    if bytes(img[off:off+ln]) != old:
        print(f"FAIL {va:#x}: {bytes(img[off:off+ln]).hex()} != {old.hex()}"); sys.exit(1)

chk(THUNK, THUNK_OLD)
chk(SQENTRY, SQ_OLD)
chk(FLIP, FLIP_OLD)
# cave areas must be pristine 0xCC
for base, ln in ((CAVE22, 0x300), (CAVE23, 0x100)):
    off = base - KTEXT
    if not all(b == 0xCC for b in img[off:off+ln]):
        print(f"FAIL cave {base:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

# --- patch sites ---
def jmp32(site, target, ln):
    off = site - KTEXT
    rel = target - (site + 5)
    img[off:off+ln] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (ln - 5)

jmp32(THUNK, CAVE22, 5)      # thunk -> cave22
jmp32(SQENTRY, CAVE23, 5)    # sleepq_add entry -> cave23
jmp32(FLIP, 0x9E9D7066, 6)   # jne -> jmp (error exit)

# --- write caves ---
off = CAVE22 - KTEXT
img[off:off+len(cave22)] = cave22
off = tbl_off - KTEXT
img[off:off+len(table)] = table
off = CAVE23 - KTEXT
img[off:off+len(cave23)] = cave23

# --- verify with capstone ---
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- thunk 0x9e65bf80 ---")
o = THUNK - KTEXT
for i in md.disasm(bytes(img[o:o+5]), THUNK):
    print(f"  {i.address:#x}  {i.bytes.hex():<14} {i.mnemonic} {i.op_str}")
print("--- sleepq_add entry 0x9f00a240 ---")
o = SQENTRY - KTEXT
for i in md.disasm(bytes(img[o:o+5]), SQENTRY):
    print(f"  {i.address:#x}  {i.bytes.hex():<14} {i.mnemonic} {i.op_str}")
print("--- flip 0x9e9d6c24 ---")
o = 0x9E9D6C24 - KTEXT
for i in md.disasm(bytes(img[o:o+8]), 0x9E9D6C24):
    print(f"  {i.address:#x}  {i.bytes.hex():<14} {i.mnemonic} {i.op_str}")
print("--- cave22 (first 30 insns) ---")
for n, i in enumerate(md.disasm(cave22, CAVE22)):
    if n >= 30: break
    print(f"  {i.address:#x}  {i.bytes.hex():<24} {i.mnemonic} {i.op_str}")
print("--- cave23 ---")
for i in md.disasm(cave23, CAVE23):
    print(f"  {i.address:#x}  {i.bytes.hex():<24} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP14: arena bootstrap (cave22) + sleepq_add guard (cave23) + sleep fail-safe")
