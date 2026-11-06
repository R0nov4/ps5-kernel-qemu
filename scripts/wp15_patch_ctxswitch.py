#!/usr/bin/env python3
"""WP15 #19 — context-switch NULL-pcb cluster fix (crash 0x9e642267 CR2=0x40).

ROOT CAUSE: the scheduler/context-switch path (0x9e642xxx — reached after
the vmwait/sleep/wake cycle) loads the thread's context:
    0x9e642227  mov r8, [r12 + 0x3f8]     ; the pcb object — NULL (the
                                          ; thread's pcb alloc never ran)
    ... lldt ...
    0x9e642267  mov eax, [r8 + 0x40]      ; <<< CRASH (r8==NULL)
    0x9e64226b  mov rdx, gs:[0x7b8]       ; TSS-ish pointer (pcpu, NULL)
    0x9e642274  mov [rdx + 2], ax         ; would crash too
    ... (symmetric block with gs:[0x7c0] / [r8+0x48]) ...
    0x9e6422aa  mov rdx, [r8 + 0x118]     ; 0 -> rdx = gs:[0x798] (0)
    0x9e6422d9  mov [rdx + 4], r8         ; would crash (rdx==NULL)
  The thread being switched to was created during SYSINIT with all its
  context objects NULL (the allocation paths are NULL-guarded).

FIX (three caves):
  cave40 @0x9E400D00 replacing [0x9e642227, 0x9e64222f):
      r8 = [r12+0x3f8]; NULL -> r8 = DMAP(0x3F1A0000) (a zero pcb seed
      page — [pcb+0x40]/[+0x48]/[+0x118]/[+0x110]/[+0x100] all read 0,
      the designed 'empty context' answers)
  cave41 @0x9E400D80 replacing [0x9e6422d0, 0x9e6422dd):
      the two gs-stores replayed; rdx == 0 -> skip '[rdx+4] = r8'
  cave42 @0x9E400E00 replacing [0x9e642267, 0x9e6422a1):
      both descriptor blocks replayed with rdx == 0 guards (skip the
      descriptor byte writes)
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE40  = 0x9E400D00
CAVE41  = 0x9E400D80
CAVE42  = 0x9E400E00
SEED    = 0xFFFF8E773F1A0000        # DMAP(0x3F1A0000) — zero pcb seed page

S40, S40E = 0x9E642227, 0x9E64222F
S41, S41E = 0x9E6422D0, 0x9E6422DD
S42, S42E = 0x9E642267, 0x9E6422A1

OLD40 = bytes.fromhex("4d8b8424f8030000")                 # mov r8,[r12+0x3f8] (8B)
OLD41 = bytes.fromhex(
    "654c89042520000000"      # mov gs:[0x20], r8    (9B)
    "4c894204"                # mov [rdx+4], r8      (4B)
)                            # 13B
OLD42 = bytes.fromhex(
    "418b4040"                # mov eax,[r8+0x40]    (4B)
    "65488b1425b8070000"      # mov rdx,gs:[0x7b8]   (8B)
    "66894202"                # mov [rdx+2],ax       (4B)
    "c1e810"                  # shr eax,0x10         (3B)
    "884204"                  # mov [rdx+4],al       (3B)
    "c1e808"                  # shr eax,8            (2B)
    "884207"                  # mov [rdx+7],al       (3B)
    "418b4048"                # mov eax,[r8+0x48]    (4B)
    "65488b1425c0070000"      # mov rdx,gs:[0x7c0]   (8B)
    "66894202"                # mov [rdx+2],ax       (4B)
    "c1e810"                  # shr eax,0x10         (3B)
    "884204"                  # mov [rdx+4],al       (3B)
    "c1e808"                  # shr eax,8            (2B)
    "884207"                  # mov [rdx+7],al       (3B)
)                            # 53B

C40 = f"""
    mov  r8, qword ptr [r12 + 0x3f8]
    test r8, r8
    jnz  ok
    movabs r8, {SEED:#x}
ok:
    jmp  {0xFFFFFFFF9E64222F:#x}
"""

C41 = f"""
    mov  qword ptr gs:[0x20], r8
    test rdx, rdx
    jnz  ok
    jmp  {0xFFFFFFFF9E6422DD:#x}
ok:
    mov  qword ptr [rdx + 4], r8
    jmp  {0xFFFFFFFF9E6422DD:#x}
"""

C42 = f"""
    mov  eax, dword ptr [r8 + 0x40]
    mov  rdx, qword ptr gs:[0x7b8]
    test rdx, rdx
    jz   skip1
    mov  word ptr [rdx + 2], ax
    shr  eax, 0x10
    mov  byte ptr [rdx + 4], al
    shr  eax, 8
    mov  byte ptr [rdx + 7], al
skip1:
    mov  eax, dword ptr [r8 + 0x48]
    mov  rdx, qword ptr gs:[0x7c0]
    test rdx, rdx
    jz   skip2
    mov  word ptr [rdx + 2], ax
    shr  eax, 0x10
    mov  byte ptr [rdx + 4], al
    shr  eax, 8
    mov  byte ptr [rdx + 7], al
skip2:
    jmp  {0xFFFFFFFF9E6422A1:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

caves = [(CAVE40, asm(C40, CAVE40), S40, OLD40, "cave40"),
         (CAVE41, asm(C41, CAVE41), S41, OLD41, "cave41"),
         (CAVE42, asm(C42, CAVE42), S42, OLD42, "cave42")]

for base, code, site, old, nm in caves:
    print(f"{nm}: {len(code):#x}B @ {base:#x}  hook {site:#x} ({len(old)}B)")
    assert len(code) <= 0x80, nm

img = bytearray(open(IMG, "rb").read())

for base, code, site, old, nm in caves:
    off = site - KTEXT
    if bytes(img[off:off+len(old)]) != old:
        print(f"FAIL {nm} site {site:#x}: {bytes(img[off:off+len(old)]).hex()}")
        print(f"  expected: {old.hex()}")
        sys.exit(1)
    off = base - KTEXT
    if not all(b == 0xCC for b in img[off:off+0x80]):
        print(f"FAIL {nm} cave {base:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

md = Cs(CS_ARCH_X86, CS_MODE_64)
for base, code, site, old, nm in caves:
    rel = base - (site + 5)
    off = site - KTEXT
    img[off:off+len(old)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(old) - 5)
    off = base - KTEXT
    img[off:off+len(code)] = code
    print(f"--- {nm} ---")
    for i in md.disasm(code, base):
        print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP15#19: context-switch NULL-pcb cluster (caves 40/41/42)")
