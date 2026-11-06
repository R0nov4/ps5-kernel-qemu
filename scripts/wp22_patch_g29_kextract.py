#!/usr/bin/env python3
"""WP22 G29 v2 — THE FAULT-FREE SOFTWARE PAGE WALK  (kextract full replacement)

THE GDB-VERIFIED ROOT CAUSE (boot #2, the one allowed GDB probe):
  * the hook + stub v1 RAN correctly — PML4[0x18C] IS present
    (0x8000000022253023, installed by the kernel's own pmap_bootstrap);
  * the crash is the kextract SLOW path translating a LOW (<2MB) VA
    (index rdx=0) whose PML4[0] (identity slot) is absent from the
    kernel's OWN new tables -> the recursive walk faults 'page not
    present' at 0xffffc66300000000;
  * i.e. kextract is called with an UNMAPPED VA (dump-code garbage /
    low address) — exactly the 'other pmap_kextract' family the user
    predicted. On a real PS5 the callers never pass such VAs.

FIX (the user's designed-answer option, upgraded to a full replacement):
  replace the WHOLE kextract fn (entry 0x9ecce330) with a software page
  walk that reads the CURRENT CR3's tables through the DMAP only:

    e0 = PML4[i0]        (DMAP(cr3 & framemask) + i0*8)
    e1 = PDPT[i1]        ... 1GB-page -> frame | (va & 0x3FFFFFFF)
    e2 = PD[i2]          ... 2MB-page -> frame | (va & 0x1FFFFF)
    e3 = PT[i3]          ... frame | (va & 0x3FFF)  [the kernel's own
                                               offset quirk, replicated]
    any level not present -> RETURN 0 (the designed not-present answer)

  No self-map dependency, no recursive reads, NO POSSIBLE FAULT.
  DMAP VAs also flow through the walk (they are 2MB-mapped -> correct
  phys, byte-identical to the original fast path for real mappings).

Registers: rdi (arg) preserved; clobbers only caller-saved
(rax=return, rcx, rdx, rsi, r8, r10, r11). Entered via the 5-byte jmp
hook at 0x9ecce330; the stub ret()s straight to the original caller.
Slot 0x9E404000, CC-verified span [0x9E404000, 0x9E404400).
Idempotent: recognizes its own hook+stub and no-ops.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"

S = 0x9ECCE330                       # kextract entry
OLD = bytes.fromhex("8b355eaf26")    # first 5 bytes of 'mov esi,[rip+0x326af5e]'
SLOT = 0x9E404000
SPAN = 0x400                         # allowed stub span (CC region)

G_D39 = 0xFFFFFFFFA1F39294           # dmap PML4 index global
G_D30 = 0xFFFFFFFFA1F39298           # dmap PDPT index global

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

C = f"""
    movabs r11, {G_D39:#x}
    mov    esi, dword ptr [r11]
    movabs r11, {G_D30:#x}
    mov    ecx, dword ptr [r11]
    mov    r8, rsi
    shl    r8, 0x27
    movabs r10, 0xFFFF800000000000
    or     r8, r10
    mov    r10, rcx
    shl    r10, 0x1e
    or     r8, r10
    movabs r11, 0x000FFFFFFFFFF000
    mov    rax, cr3
    and    rax, r11
    add    rax, r8
    mov    r10, rdi
    shr    r10, 36
    and    r10d, 0xFF8
    mov    rdx, qword ptr [rax + r10]
    test   dl, 1
    jz     answer0
    and    rdx, r11
    add    rdx, r8
    mov    r10, rdi
    shr    r10, 27
    and    r10d, 0xFF8
    mov    rax, qword ptr [rdx + r10]
    test   al, 1
    jz     answer0
    test   al, 0x80
    jnz    big1
    and    rax, r11
    add    rax, r8
    mov    r10, rdi
    shr    r10, 18
    and    r10d, 0xFF8
    mov    rdx, qword ptr [rax + r10]
    test   dl, 1
    jz     answer0
    test   dl, 0x80
    jnz    big2
    and    rdx, r11
    add    rdx, r8
    mov    r10, rdi
    shr    r10, 9
    and    r10d, 0xFF8
    mov    rax, qword ptr [rdx + r10]
    test   al, 1
    jz     answer0
    and    rax, r11
    mov    r10d, edi
    and    r10d, 0x3FFF
    or     rax, r10
    ret
big2:
    movabs r10, 0x000FFFFFFFE00000
    and    rdx, r10
    mov    r10d, edi
    and    r10d, 0x1FFFFF
    or     rdx, r10
    mov    rax, rdx
    ret
big1:
    movabs r10, 0x000FFFFFC0000000
    and    rax, r10
    mov    r10d, edi
    and    r10d, 0x3FFFFFFF
    or     rax, r10
    ret
answer0:
    xor    eax, eax
    ret
"""
code = asm(C, SLOT)
assert len(code) <= SPAN - 0x40, f"stub too big: {len(code):#x}"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

# --- hook site: idempotent ---
off = S - KTEXT
site = bytes(img[off:off + len(OLD)])
if site[:1] == b"\xe9":
    rel_expect = SLOT - (S + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    hooked = True
else:
    if site != OLD:
        print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
    hooked = False

# --- slot: accept CC / v1-stub / v2-stub (idempotent) ---
off = SLOT - KTEXT
cur = bytes(img[off:off + len(code)])
slot_ok = all(b == 0xCC for b in cur) or cur == code
if not slot_ok:
    # v1 stub residue: verify the v1 signature then overwrite
    v1_sig = bytes.fromhex("49bb9492f3a1ffffffff")
    if bytes(img[off:off + len(v1_sig)]) != v1_sig:
        print(f"FAIL slot {SLOT:#x} not pristine/v1: {cur[:16].hex()}"); sys.exit(1)

img[off:off + len(code)] = code
# clear any v1 residue beyond the v2 stub end within the span
tail = bytes(img[off + len(code):off + SPAN])
if not all(b == 0xCC for b in tail):
    img[off + len(code):off + SPAN] = b"\xCC" * (SPAN - len(code))

if not hooked:
    rel = SLOT - (S + 5)
    off = S - KTEXT
    img[off:off + len(OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP22-G29v2: fault-free software page walk @0x{S:X} "
      f"(slot 0x{SLOT:X}, stub {len(code):#x}B) — unmapped VAs answer 0")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
