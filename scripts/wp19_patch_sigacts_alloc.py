#!/usr/bin/env python3
"""WP19 #8 — fork1's child-sigacts designed allocator (cave88 @0x9E403800).

CASCADE (GDB wp19_gdb_c10..c13, Fatal trap 12 @0xffffffff9e649024
  CR2=0x0 — bzero(NULL, 0xf0)): with caves 80..87 live, fork1's kthread
  pipeline reaches the sigacts stage:
      0x9f0a2338  rdi = [r15 + 0x58]      ; proc0's sigacts — REAL (the
                                          ; boot sysinit allocated it:
                                          ; 0x9e926cc4 call sigacts_alloc
                                          ; -> [0xa1978f50])
      0x9f0a233c  rsi = [rbx + 0x58]      ; the CHILD THREAD's sigacts
                                          ; cache — NEVER SET on this boot
      0x9f0a2340  call 0x9e92d420         ; sigacts_copy(parent, child):
                                          ;   bzero(child, 0xf0)      <<<
                                          ;   bcopy(parent+0xf0 -> child+0xf0, 0x20)
                                          ;   (0x9e649be0 is BSD bcopy(src=rdi,
                                          ;    dst=rsi, len=rdx) — verified against
                                          ;    fork1's other copy sites)
  A hardware watchpoint on [child_thread+0x58], armed at the thread carve
  (cave80's return, 0x9f0a162b) and watched all the way to 0x9f0a2338,
  NEVER fires: no code in this boot's fork1 path writes the field — the
  designed writer (whoever it is on a real PS5 — the flow that forks real
  processes with working allocator state) is not part of this march.
      crash frame chain: bzero <- 0x9e92d43a <- fork1 0x9f0a2345 <-
      0x9f0a1914 <- idle_setup's WP18#8 slot <- the SYSINIT walker <-
      mi_startup.

THE FIX (the designed-object pattern for this ONE call site): hook
  [0x9f0a2340, 0x9f0a2345) (5B 'call 0x9e92d420'):
    rsi != 0  -> the designed copy (the cave calls it, returns to
                 0x9f0a2345 — untouched);
    rsi == 0  -> the DESIGNED fresh-sigacts flow, exactly what the boot
                 sysinit does for proc0:
                 1. call sigacts_alloc (0x9e92d400: malloc(0x120,
                    'sigacts-type', M_WAITOK=0x102) — WORKS on this boot,
                    it is how proc0's own sigacts was allocated);
                 2. store the fresh object at [rbx+0x58] (the very slot
                    the copy reads — rbx, the child, is callee-saved
                    across the malloc);
                 3. rsi = the fresh object; fall through to the designed
                    copy — bzero(fresh, 0xf0) + the parent's 0x20 tail;
                 4. malloc failure (NULL) -> skip the copy (the child
                    keeps NULL — the graceful designed-NULL state).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE = 0x9E403800
S     = 0x9F0A2340                       # fork1's sigacts-copy call site
SIGACTS_ALLOC = 0xFFFFFFFF9E92D400       # malloc(0x120, type, 0x102)
SIGACTS_COPY = 0xFFFFFFFF9E92D420        # bzero+bcopy(parent, child)
CONT = 0xFFFFFFFF9F0A2345                # mov rdi,[rbp-0x48] (the designed flow)

OLD = bytes.fromhex("e8dbb088ff")        # call 0x9e92d420

C = f"""
    test rsi, rsi
    jnz  do_copy
    push rbp
    push rdi
    call {SIGACTS_ALLOC:#x}
    mov  rsi, rax
    mov  qword ptr [rbx + 0x58], rax
    pop  rdi
    pop  rbp
    test rsi, rsi
    jz   skip
do_copy:
    call {SIGACTS_COPY:#x}
    jmp  {CONT:#x}
skip:
    jmp  {CONT:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C, CAVE)
print(f"cave88 @0x{CAVE:x}: {len(code):#x}B")
assert len(code) <= 0x100, "cave too big"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

off = S - KTEXT
site = bytes(img[off:off+5])
if site[:1] == b"\xe9":
    cur_target = S + 5 + int.from_bytes(site[1:5], "little", signed=True)
    if cur_target != CAVE:
        print(f"FAIL site {S:#x}: E9 -> 0x{cur_target:x} (unexpected)"); sys.exit(1)
    print(f"site {S:#x}: already hooked to cave88 (idempotent)")
    hooked = True
else:
    if site != OLD:
        print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
    hooked = False

off = CAVE - KTEXT
cur = bytes(img[off:off+len(code)])
SIG = bytes.fromhex("4885f6")   # 'test rsi, rsi' — our own cave signature
ours_before = cur[:3] == SIG
if not all(b == 0xCC for b in cur) and cur != code and not ours_before:
    print(f"FAIL cave {CAVE:#x} not pristine CC / ours: {cur[:16].hex()}"); sys.exit(1)

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE - (S + 5)
    off = S - KTEXT
    img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- fork1 child-sigacts designed allocator (cave88 @0x9E403800) ---")
for i in md.disasm(code, CAVE):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP19#8: fork1 child-sigacts designed allocator (cave88 @0x9E403800)")
