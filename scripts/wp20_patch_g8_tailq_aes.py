#!/usr/bin/env python3
"""WP20 G8 — THE 'da' TAILQ LAZY-INIT + THE AES AVX GUARD (the user's plan #8)
          [2 local guards, both caves]

GUARD A — the TAILQ lazy-init (the user's verbatim site 0x9eac2af6):
  (Fatal trap 12 @ 0xffffffff9eac2af6, CR2=0x0 WRITE — right after
   'da: Failed to attach master async callback due to status 0x7!')
    rcx = [0xa05e86a0]        ; the list's TAIL/last pointer — pristine
                              ; .data carries 0 (the head pair
                              ; {first @0xa05e8698, last @0xa05e86a0}
                              ; was never initialized on this boot)
    [rbx+8]   = r13           ; obj->prev = the old first (NULL)
    rax = rbx + 0x30
    [rbx+0x38] = rcx          ; the circular backlink = the tail
    0x9eac2af6  mov [rcx], rbx     <<< CR2 = 0x0 WRITE (rcx == NULL)
  FIX: rcx==0 -> rcx := 0xa05e8698 (&head->first — the designed
  empty-tail): [rbx+0x38] = &first; [first] = obj; the designed tail
  update makes last = obj+0x30 — the list links naturally forever after.

GUARD B — the AES key-expansion entry guard (the user's verbatim
  "AES 函数入口守卫 ... 返回 -1，因无 AVX/AES-NI"; the faulting
  instruction 0x9ebf43fd sits INSIDE this fn):
  (Fatal trap 1: privileged instruction fault — 'vmovdqu xmm0,[rsi]' +
   'vaeskeygenassist' @0x9ebf43fd: the AVX/AES-NI family this QEMU
   CPU does not implement)
    fn 0x9ebf43d0 (the aesni key-expansion, 9 call sites):
      cmp edx, 0x100 ; je ...   ; 256-bit
      cmp edx, 0xc0  ; je ...   ; 192-bit
      eax = 0xffffffff          ; the DESIGNED error value
      cmp edx, 0x80 ; jne 0x9ebf4ad0   ; 128-bit / else -> the designed
                                        ; 'unsupported' exit (eax = -1)
      0x9ebf43fd  vmovdqu xmm0, [rsi]   <<< #UD on this QEMU (no AVX)
  FIX: the fn ENTRY answers its OWN designed error: mov eax,0xffffffff;
  ret — every caller gets 'the key setup failed'; the crypto self-test
  reports its designed failure; no AVX instruction ever executes.
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

# ---------------- GUARD A: the 'da' driver list TAILQ lazy-init ---------------
SLOT_A = 0x9E402E00
S_A = 0x9EAC2AF2                                # mov [rbx+0x38],rcx; mov [rcx],rbx (7B)
OLD_A = bytes.fromhex("48894b38" + "488919")
CONT_A = 0xFFFFFFFF9EAC2AF9                     # mov [0xa05e86a0], rax (the tail update)
FIRST = 0xFFFFFFFFA05E8698                      # &head->first (the designed empty-tail)

C_A = f"""
    test rcx, rcx
    jnz  tail_ok
    movabs rcx, {FIRST:#x}
tail_ok:
    mov qword ptr [rbx + 0x38], rcx
    mov qword ptr [rcx], rbx
    jmp  {CONT_A:#x}
"""

code_a = asm(C_A, SLOT_A)
assert len(code_a) <= 0x80
cave(SLOT_A, S_A, OLD_A, code_a, "'da' TAILQ lazy-init")

# ---------------- GUARD B: the AES key-expansion entry guard -------------------
SLOT_B = 0x9E402E80
S_B = 0x9EBF43D0                                # the AES key-expansion entry (10B)
OLD_B = bytes.fromhex("554889e5" + "81fa00010000")   # push rbp; mov rbp,rsp; cmp edx,0x100

C_B = """
    mov  eax, 0xffffffff
    ret
"""

code_b = asm(C_B, SLOT_B)
assert len(code_b) <= 0x80
cave(SLOT_B, S_B, OLD_B, code_b, "AES key-expansion entry guard (-1)")

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print("OK WP20-G8: da-TAILQ lazy-init + AES AVX entry guard — no trap, no #UD")
