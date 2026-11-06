#!/usr/bin/env python3
"""WP20 G13 — THE DEEP-MARCH NULL-SKIP FAMILY  [NEW FRONTIER]
          [3 local cave guards — the post-'Device configuration finished.'
            allocation sites, each taking its OWN designed skip]

GUARD A — the if_attach record NULL-skip (crash 0x9e8aa9b7, CR2=0x68):
  if_attach's name-record builder allocs (2*align8(len+0x1f)+0x68) via
  the DESIGNED NULL allocator 0x9e8ac340, then writes [r15+0x68].  The
  7B window (mov r15,rax; add rax,0x68) is hooked; the cave replays both
  on success, and on NULL skips the whole record block (field stores,
  name copy, 0xff prefill, TAILQ append) to 0x9e8aaabc — replaying ONLY
  the [rbp-0x30]=r12 store that 0x9e8aad08 later reads.

GUARD B — the 16KB-contig thunk NULL-skip (crash 0x9ebc46c4, CR2=0x18):
  the thunk's 'lea rdi,[rax+0x18]' after the 0x9e84d9c0 contig allocator
  returned NULL.  The cave replays the call; NULL takes the thunk's own
  epilogue (add rsp,0x10; pop rbx; pop r14; pop rbp; ret).

GUARD C — the zone-item register NULL-skip (crash 0x9ed52c45, CR2=0x10):
  the UMA zone-item alloc 0x9e82b880 answered NULL; the caller writes
  the config record at [rax+0x10].  The cave replays the alloc; NULL
  jumps to the designed exit join 0x9ed52cfb (which needs only
  r15/[rbp-0x30]/ebx — all pre-set).
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
    print(f"OK {label}")

# ---------------- GUARD A: if_attach record NULL-skip --------------------------
SLOT_A = 0x9E403A80
S_A = 0x9E8AA9A2                                # mov r15,rax; add rax,0x68 (7B)
OLD_A = bytes.fromhex("4989c748" + "83c068")
CONT_A = 0xFFFFFFFF9E8AA9A9                     # movsxd rdx,r13d (designed)
SKIP_A = 0xFFFFFFFF9E8AAABC                     # after the record block

C_A = f"""
    test rax, rax
    jz   null_path_a
    mov  r15, rax
    add  rax, 0x68
    jmp  {CONT_A:#x}
null_path_a:
    mov  qword ptr [rbp - 0x30], r12
    jmp  {SKIP_A:#x}
"""
cave(SLOT_A, S_A, OLD_A, asm(C_A, SLOT_A), "if_attach record NULL-skip")

# ---------------- GUARD B: 16KB-contig thunk NULL-skip --------------------------
SLOT_B = 0x9E403B00
S_B = 0x9EE816C5                                # call 0x9e84d9c0 (5B)
OLD_B = bytes.fromhex("e8f6c29cff")
ALLOC_B = 0xFFFFFFFF9E84D9C0
CONT_B = 0xFFFFFFFF9EE816CA                     # lea rdi,[rax+0x18]

C_B = f"""
    call {ALLOC_B:#x}
    test rax, rax
    jz   null_path_b
    jmp  {CONT_B:#x}
null_path_b:
    add  rsp, 0x10
    pop  rbx
    pop  r14
    pop  rbp
    ret
"""
cave(SLOT_B, S_B, OLD_B, asm(C_B, SLOT_B), "16KB-contig thunk NULL-skip")

# ---------------- GUARD C: zone-item register NULL-skip -------------------------
SLOT_C = 0x9E403B80
S_C = 0x9ED52C2B                                # call 0x9e82b880 (5B)
OLD_C = bytes.fromhex("e8508cadff")
ALLOC_C = 0xFFFFFFFF9E82B880
CONT_C = 0xFFFFFFFF9ED52C30                     # lea r12,[rip+...] (designed)
EXIT_C = 0xFFFFFFFF9ED52CFB                     # the designed exit join

C_C = f"""
    call {ALLOC_C:#x}
    test rax, rax
    jz   null_path_c
    jmp  {CONT_C:#x}
null_path_c:
    jmp  {EXIT_C:#x}
"""
cave(SLOT_C, S_C, OLD_C, asm(C_C, SLOT_C), "zone-item register NULL-skip")

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print("OK WP20-G13: the deep-march NULL-skip family (3 guards)")
