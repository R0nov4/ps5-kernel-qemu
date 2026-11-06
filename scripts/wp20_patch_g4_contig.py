#!/usr/bin/env python3
"""WP20 G4 — THE CONTIGMALLOC / VM_PHYS FAIL-FAST FAMILY (the user's plan #4)
          [4 local guards: 2 in-place branch retargets + 2 caves]

THE STALL FAMILY (the user's GDB findings):
  (a) SYSINIT IDX 854 (a sub=0x13 entry asking a 0x20000 contiguous
      allocation): contig alloc 0x9eff8910 -> 0x9e8f3af0 -> fn 0x9e8f3800
      (the vm_page domain retry loop):
        0x9e8f3a30  <head>: the domain lock; the ONE alloc attempt
        0x9e8f3a6d  test rax,rax; jne ...            ; SUCCESS
        0x9e8f3a82  dec r13d
        0x9e8f3a85  je 0x9e8f3ad0                    ; the counter bound
        0x9e8f3a87  ... the scan 0x9ef7b780 setup ...
        0x9e8f3aa7  call 0x9ef7b780                  ; the free-list walk —
                                                    ; PERMANENTLY empty, and
                                                    ; ONE call grinds for
                                                    ; minutes under TCG
        0x9e8f3ab4  je 0x9e8f3a30                    <<< THE RETRY (bit1 clear)
      The designed exhaustion exit 0x9e8f3ad0 (notify + xor eax,eax ->
      NULL -> the caller's designed failure -> the SYSINIT's own error
      path) NEVER runs because the scan eats all the time first.

  (b) The zone-free family: 0x9e82c0c0(rdi=ZONE=NULL) reads [rdi+0x98]
      -> CR2=0x98; the registry-drain fn 0x9e9d7750 reads the NULL
      sentinel [rbx+0x10] -> CR2=0x10 — both called from the contig
      failure unwind / the notify path.

THE USER'S FIX (verbatim): "在 0x9eff8910 与 0x9e8f3af0 加入口守卫，或把
  0x9e8f3800 的重试计数 r13d 缩短并走出口 0x9e8f3ad0" — we take the
  surgical variant (the retry loop exits through its OWN designed
  exhaustion exit) plus the two rdi==NULL guards:

  SITE A  0x9e8f3ab4: je 0x9e8f3a30 -> je 0x9e8f3ad0   (6B rel32 retarget)
          — the retry branch now takes the designed exhaustion exit
          immediately.
  SITE B  0x9e8f3a85: je -> jmp (74 49 -> eb 49)        (2B opcode)
          — the counter bound ALWAYS fires: loop head -> one alloc
          attempt -> the designed exhaustion exit.  The scan, the
          vm_wait and the whole retry tail become unreachable dead
          code.  Result: 'contigmalloc failed.' + the SYSINIT's own
          error print, the pfsmgr stage passes.
  SITE C  0x9e9d77a7 (list-drain, slot 0x9E402C00): sentinel NULL ->
          the designed empty-list exit 0x9e9d780a.
  SITE D  0x9e82c0e8 (zone-free, slot 0x9E402C80): ZONE NULL -> the
          fn's OWN designed NULL-item epilogue 0x9e82cbe4.
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

def save():
    open(IMG, "wb").write(img)
    assert len(img) == 65224704, "SIZE MISMATCH"

# ---------------- SITE A: the retry branch -> the exhaustion exit -------------
S_A = 0x9E8F3AB4
OLD_A = bytes.fromhex("0f8476ffffff")          # je 0x9e8f3a30 (the retry)
NEW_A = bytes.fromhex("0f8416000000")          # je 0x9e8f3ad0 (the exhaustion)
off = S_A - KTEXT
site = bytes(img[off:off+6])
if site == NEW_A:
    print(f"site A {S_A:#x}: already retargeted (idempotent)")
elif site == OLD_A:
    img[off:off+6] = NEW_A
    print(f"OK site A: retry je -> exhaustion exit @ {S_A:#x}")
else:
    print(f"FAIL site A {S_A:#x}: {site.hex()}"); sys.exit(1)

# ---------------- SITE B: the counter bound je -> jmp -------------------------
S_B = 0x9E8F3A85
OLD_B = bytes.fromhex("7449")                  # je 0x9e8f3ad0
NEW_B = bytes.fromhex("eb49")                  # jmp 0x9e8f3ad0 (ALWAYS)
off = S_B - KTEXT
site = bytes(img[off:off+2])
if site == NEW_B:
    print(f"site B {S_B:#x}: already hardened (idempotent)")
elif site == OLD_B:
    img[off:off+2] = NEW_B
    print(f"OK site B: counter-bound je -> jmp @ {S_B:#x}")
else:
    print(f"FAIL site B {S_B:#x}: {site.hex()}"); sys.exit(1)

# ---------------- SITE C: list-drain NULL sentinel (cave) ---------------------
SLOT_C = 0x9E402C00
S_C = 0x9E9D77A7                                # mov rcx,[rbx+0x10] + REX '4c'
OLD_C = bytes.fromhex("488b4b10" + "4c")
CONT_C = 0xFFFFFFFF9E9D77AF                     # test rcx,rcx (the designed check)
EXIT_C = 0xFFFFFFFF9E9D780A                     # the designed empty-list exit

C_C = f"""
    test rbx, rbx
    jnz  live_c
    jmp  {EXIT_C:#x}
live_c:
    mov  rcx, qword ptr [rbx + 0x10]
    lea  r14, [rbx + 0x10]
    jmp  {CONT_C:#x}
"""

# ---------------- SITE D: zone-free NULL zone (cave) ---------------------------
SLOT_D = 0x9E402C80
S_D = 0x9E82C0E8                                # mov r14,[rdi+0x98] (7B, hook 5)
OLD_D = bytes.fromhex("4c8bb798" + "00")
CONT_D = 0xFFFFFFFF9E82C0EF                     # mov r12,rdx (intact continuation)
EPI_D = 0xFFFFFFFF9E82CBE4                     # the designed NULL-item epilogue

C_D = f"""
    test rdi, rdi
    jnz  have_zone
    jmp  {EPI_D:#x}
have_zone:
    mov  r14, qword ptr [rdi + 0x98]
    jmp  {CONT_D:#x}
"""

def cave(SLOT, S, OLD, code, label):
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
        img[off:off+len(OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD) - 5)
    print(f"--- {label} (slot {SLOT:#x}) ---")
    for i in md.disasm(code, SLOT):
        print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
    print(f"OK {label}: hook {S:#x} -> slot {SLOT:#x}")

code_c = asm(C_C, SLOT_C)
assert len(code_c) <= 0x80
cave(SLOT_C, S_C, OLD_C, code_c, "list-drain NULL-sentinel skip")

code_d = asm(C_D, SLOT_D)
assert len(code_d) <= 0x80
cave(SLOT_D, S_D, OLD_D, code_d, "zone-free NULL-zone guard")

save()
print("OK WP20-G4: contigmalloc/vm_phys fail-fast family (4 guards) — "
      "'contigmalloc failed.' + pfsmgr next")
