#!/usr/bin/env python3
"""WP17 #1 — the Zone/Chunk family: drain guard + hook3 NULL-symmetry + the
systemic zone-table seed (crash 0xffffffff9e82b788, CR2=0x98 READ).

ROOT CAUSE (GDB wp17_gdb_c1/c2):
  The post-APIC SYSINIT stage (a hashinit-style bootstrap: tunable-driven
  element count @0xa2179c4c = 0x3cd4 -> malloc(0xF3500, type, 0x8002)) takes
  the malloc LARGE path 0x9e82e080:
    rax = zone_chunk_alloc([0xa18ea8c0], ...)   <- the zone-table global = NULL
    r15 = rax (the cave56-bumped 16KB chunk page 0x3F1AB6F0)
    rax = fill_loop(0x9e8f3d80)([0x9fed8b18] arena, 0xF4000, flags)
        -> kmem_alloc 0x9e9d6730: [arena+0x3e8]=0 -> SLOW path 0x9e9d67c0
        -> the extend thunk [arena+0x428] = NULL (the arena struct was
           WIPED by a later SYSINIT after WP16#15's cave57 seeded it)
        -> wait-fail (cave57: reseed + NOWAIT-fail 0xc)
    rax == NULL -> the designed unwind:
        rdi = [0xa18ea8c0] = NULL; rsi = r15 (the chunk)
        call 0x9e82b760 (zone_drain)  -> 'mov r15,[rdi+0x98]' -> CR2=0x98.

  The drain fn 0x9e82b760 (prologue .. epilogue dissected):
    [rbp-0x28] = vm_reserv counter entry value; [rbp-0x30] = arg2
    r15 = [zone+0x98]  hook1  (NULL -> designed skip 'test/je')
    r15 = [zone+0xa8]  hook2  (NULL -> designed skip 'test/je')
    lock add [zone+0x110], 1                       (ops counter)
    r14 = [zone+0xb8]  hook3  (*** NO designed NULL check *** -> validated
        against the 20-slot thunk array [0x9e658140,0x9e6581d8]; a NULL
        r14 fails the range check -> the warn printer 0x9e83f8c0 -> then
        'call r14' = call NULL)
    hook3([zone+0xc0], &arg2, 1); counter balance check; ret.

FIX (3 layers, per the user's WP17 directive):
  A) cave63 @0x9E401880 — entry guard on the drain fn:
     hook [0x9e82b760,0x9e82b765) ('push rbp; mov rbp,rsp; 41'):
       rdi == 0 (the NULL zone) -> plain 'ret' AT THE ENTRY (nothing was
       modified yet — completely clean for all 8 callers);
       else replay 'push rbp; mov rbp,rsp; push r15' -> 0x9e82b766.
     The failed chunk leaks (bump memory — harmless, cave51 philosophy).
  B) cave64 @0x9E401900 — hook3 NULL-symmetry:
     hook [0x9e82b7fc,0x9e82b803) ('mov r14,[rbx+0xb8]', 7B):
       r14 == 0 -> jump 0x9e82b823 (the balance check + epilogue — hook3
       skipped exactly like the designed hook1/hook2 NULL skips);
       else replay the load -> the designed validation + hook3 call.
  C) THE SYSTEMIC ZONE-TABLE SEED:
     [0xa18ea8c0] := DMAP(0x3F1A0880) — a pristine-zero page in the seed
     area's scratch gap [0x3F1A0840,0x3F1A1000) (below the malloc window,
     above the bump-ptr slots; zeroed by the trampoline's seed-area fill).
     The zero zone: hook1/hook2 NULL (designed skips), import +0xb0 NULL
     (cave56's bump), hook3 NULL (cave64's skip), +0x110 the lock-add
     target (a harmless write into the zero page). The whole 0x9e82bxxx
     family now reads valid memory; the zone-create path (WRITE @0x9e829a05)
     can still overwrite the seed later (the designed flow wins).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE63 = 0x9E401880
CAVE64 = 0x9E401900
S63, S63E = 0x9E82B760, 0x9E82B765          # push rbp; mov rbp,rsp; [41]57 (5B)
S64, S64E = 0x9E82B7FC, 0x9E82B803          # mov r14,[rbx+0xb8] (7B)
SKIP3 = 0xFFFFFFFF9E82B823                   # the balance-check head (hook3 skipped)
CONT3 = 0xFFFFFFFF9E82B803                   # the designed validation head
CONT63 = 0xFFFFFFFF9E82B766                  # 'push r14' (the designed prologue tail)

ZONE_GLOBAL = 0xA18EA8C0                      # the zone-table global (.data, SHORT va: img offset = VA-KTEXT)
SEED_ZONE = 0xFFFF8E773F1A0880               # DMAP(0x3F1A0880) — pristine zero page

OLD63 = bytes.fromhex("554889e541")          # push rbp; mov rbp,rsp; 41
OLD64 = bytes.fromhex("4c8bb3b8000000")      # mov r14,[rbx+0xb8]

C63 = f"""
    test rdi, rdi
    jz   nullret
    push rbp
    mov  rbp, rsp
    push r15
    jmp  {CONT63:#x}
nullret:
    ret
"""

C64 = f"""
    mov  r14, qword ptr [rbx + 0xb8]
    test r14, r14
    jnz  have3
    jmp  {SKIP3:#x}
have3:
    jmp  {CONT3:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code63 = asm(C63, CAVE63)
code64 = asm(C64, CAVE64)
print(f"cave63: {len(code63):#x}B @ {CAVE63:#x}  hook {S63:#x} (5B)")
print(f"cave64: {len(code64):#x}B @ {CAVE64:#x}  hook {S64:#x} (7B)")
assert len(code63) <= 0x80 and len(code64) <= 0x80

img = bytearray(open(IMG, "rb").read())

def hook_site(site, old, cave, n_displaced):
    off = site - KTEXT
    cur = bytes(img[off:off+len(old)])
    if cur[:1] == b"\xe9":
        rel_expect = cave - (site + 5)
        if cur[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
            print(f"FAIL site {site:#x} hooked elsewhere: {cur[:5].hex()}"); sys.exit(1)
        print(f"site {site:#x}: already hooked -> {cave:#x} (idempotent)")
        return True
    if cur != old:
        print(f"FAIL site {site:#x}: {cur.hex()} != {old.hex()}"); sys.exit(1)
    return False

def check_cave(cave, code):
    off = cave - KTEXT
    cur = bytes(img[off:off+len(code)])
    if not all(b == 0xCC for b in cur):
        if cur == code:
            print(f"cave {cave:#x}: body already present")
            return False   # rewrite anyway (idempotent)
        print(f"FAIL cave {cave:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)
    return True

h63 = hook_site(S63, OLD63, CAVE63, 5)
h64 = hook_site(S64, OLD64, CAVE64, 7)
c63ok = check_cave(CAVE63, code63)
c64ok = check_cave(CAVE64, code64)

# --- the systemic zone-table seed ---
off_g = ZONE_GLOBAL - KTEXT
cur_g = bytes(img[off_g:off_g+8])
seed_q = SEED_ZONE.to_bytes(8, "little")
if cur_g == seed_q:
    print(f"zone seed [0xa18ea8c0] already = {SEED_ZONE:#x}")
elif cur_g == b"\x00" * 8:
    print(f"zone-table global [0xa18ea8c0]: zero (never created) -> seeding")
elif cur_g == bytes.fromhex("00af5fff778effff"):
    # live-dump residue of the real runtime zone — wipe to OUR seed
    print(f"zone-table global [0xa18ea8c0]: live residue {cur_g.hex()} -> reseeding")
else:
    print(f"WARN zone-table global unexpected value {cur_g.hex()} -> reseeding anyway")

img[off_g:off_g+8] = seed_q

# --- write the caves + the hooks ---
off = CAVE63 - KTEXT
img[off:off+len(code63)] = code63
off = CAVE64 - KTEXT
img[off:off+len(code64)] = code64

if not h63:
    rel = CAVE63 - (S63 + 5)
    off = S63 - KTEXT
    img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)
if not h64:
    rel = CAVE64 - (S64 + 5)
    off = S64 - KTEXT
    img[off:off+len(OLD64)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD64) - 5)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave63 (drain entry guard) ---")
for i in md.disasm(code63, CAVE63):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
print("--- cave64 (hook3 NULL-symmetry) ---")
for i in md.disasm(code64, CAVE64):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
print(f"--- zone seed: [0xa18ea8c0] := {SEED_ZONE:#x} (zero zone @0x3F1A0880) ---")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP17#1: zone-drain guard + hook3 NULL-symmetry + zone-table seed")
