#!/usr/bin/env python3
"""WP19 #1 — fork1's THREAD-object real allocator (cave80 @0x9E402A80).

THE WP19 ROOT-CAUSE FINDING (GDB attach at the post-'gc_suspend_resume'
silence, ~15s and ~60s after the line):
  The SYSINIT march is NOT complete and NOT in cpu_idle — the walker is
  stuck INSIDE sysinit IDX 735 of 1236 slots (the first entry of the
  sub=0x13 group: the GEOM 'g_blk' class registration):
      mi_startup -> 0x9e65d710 (thunk) -> 0x9e9750a0 (the class/module
      runner, udata name 'g_blk') -> module handler -> 0x9ebab9e0 =
      g_post_event_x(fmt string 'g_post_event_x(%p, %p, %d, %d)' confirmed)
      -> posts a GEOM event with EV_WAIT(0x100) and polls
      'while (!(ep->flag & EV_DONE=0x80000)) msleep(ep, &g_eventlock,
      0x4c, "g_waitfor_event", hz)' forever.
  EV_DONE would be set by the GEOM worker threads (the g_down body lives
  at 0x9ee34440) — which were NEVER created: kthread_create -> fork1 ->
  zone_alloc([0xa1979e30]=NULL THREAD zone) -> NULL -> error 12.
  mi_switch(0x9eaa5a60) keeps answering thread0 (empty runq ->
  PCPU(idlethread)=gs:[8]=thread0, the WP16#2 seed) so the sleep retries
  silently forever: alive, no trap, no panic, serial-quiet.

THE FIX (the user's WP19 mission #2 — the designed-object path for this
  ONE call site, the general zone_create path untouched):
  fork1's thread-alloc call [0x9f0a1626, 0x9f0a162b) (5B 'call
  0x9e82b880', rdi=[0xa1979e30] the THREAD zone — size 0xCE8, created at
  0x9e92b8ed via the size probe 0x9eaa7ad0):
    replay the original zone-alloc;
    rax != 0  -> the zone answered — the designed path (jmp 0x9f0a162b);
    rax == 0  -> THE WP19 PATH: carve a page-aligned, zeroed 0xCE8 THREAD
                 object from the SHARED malloc/zone bump window
                 [0x3F1A1000, 0x3F740000) using the SAME cursor global
                 [DMAP(0x3F1A0830)] that cave50/56 (WP17#4) use — the
                 cursor is read, page-aligned, advanced past the carve
                 and stored back: zero collisions with the runtime bump
                 by construction. The object is bzero'd via the kernel's
                 own bzero (0x9e648ff0) — the fresh-UMA-slab semantics —
                 then the thread-list head at [+0x10/+0x18] gets its
                 designed LIST_INIT seed ([+0x10]=NULL first (bzero'd),
                 [+0x18] := &first — the self-pointer the TAILQ insert
                 at 0x9ef800d7-0x9ef800e2 requires).
    window exhausted -> the WP18#5 designed ENOMEM protocol:
                 eax := 0xc, fork1's own 6-pop epilogue.
  The hook re-points the EXISTING WP18#5 E9 at 0x9f0a1626 from slot
  0x9E401E80 to the new cave80 @0x9E402A80 (the ledger's next-free slot).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE = 0x9E402A80                       # next free per the WP18 ledger
S     = 0x9F0A1626                      # the fork1 thread-alloc call site
OLD_SLOT = 0x9E401E80                   # the WP18#5 slot (current E9 target)
ZONEALLOC = 0xFFFFFFFF9E82B880          # the original zone-alloc wrapper
BZERO = 0xFFFFFFFF9E648FF0              # the kernel's bzero(rdi, rsi)
CONT = 0xFFFFFFFF9F0A162B               # mov r15,[rax+0x10] — the designed deref
THREAD_SIZE = 0xCE8                     # the THREAD zone object size (0x9e92b8ed)

CURSOR = 0xFFFF8E773F1A0830             # the shared bump-window cursor
BASE   = 0xFFFF8E773F1A1000             # window base
CEIL   = 0xFFFF8E773F740000             # window ceiling (WP17#4's 5.6MB)

C = f"""
    call {ZONEALLOC:#x}
    test rax, rax
    jnz  done
    push rbp
    mov  r10, {CURSOR:#x}
    mov  rax, qword ptr [r10]
    test rax, rax
    jnz  have_cur
    movabs rax, {BASE:#x}
have_cur:
    add  rax, 0xfff
    and  rax, -4096
    movabs rdx, {BASE:#x}
    cmp  rax, rdx
    jb   window_full
    movabs rdx, {CEIL:#x}
    cmp  rax, rdx
    jae  window_full
    lea  r11, [rax + {THREAD_SIZE:#x}]
    cmp  r11, rdx
    ja   window_full
    mov  qword ptr [r10], r11
    push rax
    mov  rdi, rax
    mov  esi, {THREAD_SIZE:#x}
    call {BZERO:#x}
    pop  rax
    lea  rcx, [rax + 0x10]
    mov  qword ptr [rax + 0x18], rcx
    pop  rbp
done:
    jmp  {CONT:#x}
window_full:
    pop  rbp
    mov  eax, 0xc
    add  rsp, 0x38
    pop  rbx
    pop  r12
    pop  r13
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

code = asm(C, CAVE)
print(f"cave80 @0x{CAVE:x}: {len(code):#x}B")
assert len(code) <= 0x180, "cave too big"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

# --- verify + re-point the site: must be E9 -> OLD_SLOT (hooked by WP18#5) ---
off = S - KTEXT
site = bytes(img[off:off+5])
if site[:1] == b"\xe9":
    cur_target = S + 5 + int.from_bytes(site[1:5], "little", signed=True)
    if cur_target == CAVE:
        print(f"site {S:#x}: already points at cave80 (idempotent)")
    elif cur_target == OLD_SLOT:
        print(f"site {S:#x}: WP18#5 E9 -> 0x{OLD_SLOT:x} confirmed, re-pointing to cave80")
    else:
        print(f"FAIL site {S:#x}: E9 -> 0x{cur_target:x} (unexpected)"); sys.exit(1)
else:
    print(f"FAIL site {S:#x}: {site.hex()} is not an E9 hook (run WP18#5 first)"); sys.exit(1)

# --- verify the cave area is pristine CC (or already ours) ---
off = CAVE - KTEXT
cur = bytes(img[off:off+len(code)])
SIG = bytes.fromhex("4885c0")   # 'test rax, rax' — our own cave signature (after the replay call)
ours_before = cur[:1] == b"\xe8" and SIG in cur[:12]
if not all(b == 0xCC for b in cur) and cur != code and not ours_before:
    print(f"FAIL cave {CAVE:#x} not pristine CC / ours: {cur[:16].hex()}"); sys.exit(1)

img[off:off+len(code)] = code

# --- (re)point the site E9 at the cave ---
rel = CAVE - (S + 5)
off = S - KTEXT
img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- fork1 THREAD-object real allocator (cave80 @0x9E402A80) ---")
for i in md.disasm(code, CAVE):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP19#1: fork1 THREAD-object real allocator (cave80 @0x9E402A80)")
