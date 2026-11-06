#!/usr/bin/env python3
"""WP20 G10 — THE DOMAIN FREE-NODE POP EMPTY-QUEUE FAMILY  [NEW FRONTIER]
          [3 local guards: the two designed skips in the engine fn +
            the node-create entry no-op — closes ALL FOUR pop paths]
          (crash 0xffffffff9e9d803e, CR2=0x10 READ — right after
           'hmd2_imu:kproc_create error 12', before 'io: <I/O>')

THE FAMILY: fn 0x9e9d8030 pops the head node of a free-node queue:

    0x9e9d8037  rax = [rdi+0x408]        ; the parked head node
    0x9e9d803e  rcx = [rax+0x10]         <<< CR2=0x10: head == NULL
    ...        TAILQ-remove rax; 'dec [rdi+0x410]'; ret rax

  The callers DEREF the popped node immediately (no NULL answer exists
  in the design — the node queues were seeded at init). The wiped
  cold-boot .data leaves the head NULL while the count says 'pending'.

  Exactly FOUR callers exist (xref-verified):
    engine fn 0x9e9d67c0 site 1  @0x9e9d6cff   -> designed skip 0x9e9d6d94
    engine fn 0x9e9d67c0 site 2  @0x9e9d6db5   -> designed skip 0x9e9d6dff
    node-create fn 0x9e9d7990    @0x9e9d79aa   \
    node-create fn 0x9e9d7990    @0x9e9d79dd   / (its caller IGNORES
                                    the return — only side effects matter)

THE LOCAL GUARDS (the WP18 doctrine — each consumer takes its OWN
  designed 'nothing to give' continuation):
  GUARD 1  hook [0x9e9d6cf8, +5): rbx=[rbp-0x58] replayed; if
           [rbx+0x408]==NULL -> jmp 0x9e9d6d94 (the 'cmp/je' target —
           the designed 'no node' continuation); else mov rdi,rbx and
           the designed pop call.
  GUARD 2  hook [0x9e9d6daf, +5): if [r12+0x408]==NULL -> jmp
           0x9e9d6dff (the 'je/jbe' targets — the designed 'no reclaim'
           continuation); else mov rdi,r12; mov rbx,rcx and the call.
  GUARD 3  hook [0x9e9d7990, +5) (the node-create ENTRY): if
           [rdi+0x408]==NULL -> plain ret (nothing pushed yet — a clean
           no-op; the caller ignores the result by design); else the
           prologue replays and the fn runs designed.
  The pop fn ITSELF stays untouched (the working early-boot flow —
  the vm_page_startup table supply path — keeps its real nodes).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

def guard(SLOT, S, OLD, code, label):
    off = S - KTEXT
    site = bytes(img[off:off+len(OLD)])
    if site[:1] == b"\xe9":
        rel_expect = SLOT - (S + 5)
        if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
            print(f"FAIL {label} site {S:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
        hooked = True
    else:
        if site != OLD:
            print(f"FAIL {label} site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
        hooked = False
    off2 = SLOT - KTEXT
    cur = bytes(img[off2:off2+len(code)])
    if not all(b == 0xCC for b in cur) and cur != code:
        print(f"FAIL {label} slot {SLOT:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)
    img[off2:off2+len(code)] = code
    if not hooked:
        rel = SLOT - (S + 5)
        img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)   # exactly 5B
    print(f"--- {label} (slot {SLOT:#x}) ---")
    for i in md.disasm(code, SLOT):
        print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
    print(f"OK {label}")

# --- GUARD 1: engine site 1 (0x9e9d6cf8: mov rbx,[rbp-0x58]; mov rdi,rbx) ---
S1 = 0x9E9D6CF8
SLOT1 = 0x9E403300
SKIP1 = 0xFFFFFFFF9E9D6D94               # the designed skip (site 1)
OLD1 = bytes.fromhex("488b5da8" + "4889df")   # mov rbx,[rbp-0x58]; mov rdi,rbx
C1 = f"""
    mov  rbx, qword ptr [rbp - 0x58]
    cmp  qword ptr [rbx + 0x408], 0
    jne  live1
    jmp  {SKIP1:#x}
live1:
    mov  rdi, rbx
    jmp  {0xFFFFFFFF9E9D6CFF:#x}
"""
guard(SLOT1, S1, OLD1, asm(C1, SLOT1), "engine pop site-1 skip")

# --- GUARD 2: engine site 2 (0x9e9d6daf: mov rdi,r12; mov rbx,rcx) ---
S2 = 0x9E9D6DAF
SLOT2 = 0x9E403380
SKIP2 = 0xFFFFFFFF9E9D6DFF               # the designed skip (site 2)
OLD2 = bytes.fromhex("4c89e7" + "4889")  # mov rdi,r12; (REX of mov rbx,rcx)
C2 = f"""
    cmp  qword ptr [r12 + 0x408], 0
    jne  live2
    jmp  {SKIP2:#x}
live2:
    mov  rdi, r12
    mov  rbx, rcx
    jmp  {0xFFFFFFFF9E9D6DB5:#x}
"""
guard(SLOT2, S2, OLD2, asm(C2, SLOT2), "engine pop site-2 skip")

# --- GUARD 3: the node-create entry no-op (0x9e9d7990) ---
S3 = 0x9E9D7990
SLOT3 = 0x9E403400
OLD3 = bytes.fromhex("554889e5" + "41")  # push rbp; mov rbp,rsp; (REX of push r15)
C3 = f"""
    cmp  qword ptr [rdi + 0x408], 0
    jne  live3
    ret
live3:
    push rbp
    mov  rbp, rsp
    push r15
    jmp  {0xFFFFFFFF9E9D7996:#x}
"""
guard(SLOT3, S3, OLD3, asm(C3, SLOT3), "node-create entry no-op")

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print("OK WP20-G10: domain free-node pop family (3 guards) — all four pop "
      "paths closed, 'io: <I/O>' next")
