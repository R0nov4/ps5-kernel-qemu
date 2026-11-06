#!/usr/bin/env python3
"""WP13 cave relocation — move risky caves into the GUARANTEED-dead P5 body.

Discovery: the "dead ICC body" ends at the P5 stub (0x9EE30CA0 = 31 c0 c3,
WP7 ICC-recovery defuse). 0x9EE30DB0+ is LIVE code (GART/region-manager
family: live fns at 0x9EE30DB0, 0x9EE30EF0, 0x9EE30FC0 — the last one broke
the boot when cave17 overwrote its loop at 0x9EE31000).  cave15 (0x9EE30E00)
and cave16 (0x9EE30F00) sit INSIDE live functions — time bombs; relocate.

Safe dead space: P5 stub body 0x9EE30CA3..0x9EE30D9F (entry stubbed, dead)
minus cave13 (0x9EE30D00..0x9EE30D32).
New homes:
    cave16 (lock-init leaf guard, fix #9)  0x9EE30F00 -> 0x9EE30D40 (20B)
    cave15 (kern_env seed,      fix #8)    0x9EE30E00 -> 0x9EE30D60 (51B)
    cave17 (mtx_init guard,     fix #10)   0x9EE31000 -> 0x9EE30CA8 (31B)
Jump sites re-targeted accordingly.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
PRISTINE = "./kit_build/pristine/kernel_raw.bin"

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

img = bytearray(open(IMG, "rb").read())
pristine = open(PRISTINE, "rb").read()

def asm(code, base):
    enc, _ = ks.asm(code, base)
    return bytes(enc)

def check_p5():
    off = 0x9EE30CA0 - KTEXT
    assert bytes(img[off:off+3]) == bytes.fromhex("31c0c3"), "P5 stub missing!"
    print("P5 stub @0x9EE30CA0 intact (31 c0 c3) — body 0x9EE30CA3..0x9EE30D9F is dead")

check_p5()

# ---- 1. restore old cave15/16 areas from pristine ----
for va, ln in ((0x9EE30E00, 51), (0x9EE30F00, 20), (0x9EE31000, 31)):
    off = va - KTEXT
    img[off:off+ln] = pristine[off:off+ln]
    print(f"restored pristine {ln}B @ {va:#x}")

# ---- 2. cave16 (lock-init leaf guard) @0x9EE30D40 ----
CAVE16 = 0x9EE30D40
cave16 = asm("""
test rdi, rdi
jz clean_ret
test rdx, rdx
jz 0x9ee1e9df
jmp 0x9ee1e8d9
clean_ret:
ret
""", CAVE16)
assert len(cave16) == 20, len(cave16)
img[CAVE16-KTEXT:CAVE16-KTEXT+len(cave16)] = cave16

# re-target the leaf entry jmp 0x9ee1e8d0 -> CAVE16
off = 0x9ee1e8d0 - KTEXT
rel = CAVE16 - (0x9ee1e8d0 + 5)
img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)
print(f"cave16 -> {CAVE16:#x}, leaf jmp re-targeted")

# ---- 3. cave15 (kern_env seed) @0x9EE30D60 ----
CAVE15 = 0x9EE30D60
cave15 = asm("""
test rax, rax
jnz real
movabs rcx, 0xffff8e773f002000
movabs rdx, 0xffffffffa191b560
mov qword ptr [rdx], rcx
jmp 0x9e86e022
real:
movabs rdx, 0xffffffffa191b560
mov qword ptr [rdx], rax
jmp 0x9e86e022
""", CAVE15)
assert len(cave15) == 51, len(cave15)
img[CAVE15-KTEXT:CAVE15-KTEXT+len(cave15)] = cave15

# re-target the store-site jmp 0x9e86e01b -> CAVE15
off = 0x9e86e01b - KTEXT
rel = CAVE15 - (0x9e86e01b + 5)
img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)
img[off+5:off+7] = b"\x90\x90"
print(f"cave15 -> {CAVE15:#x}, store jmp re-targeted")

# ---- 4. cave17 (mtx_init entry guard) @0x9EE30CA8 ----
CAVE17 = 0x9EE30CA8
cave17 = asm("""
test rdi, rdi
jz null_ret
movabs rax, 0x1000
cmp rdi, rax
jb null_ret
push rbp
mov rbp, rsp
push rbx
jmp 0x9e8b7dd5
null_ret:
ret
""", CAVE17)
print(f"cave17: {len(cave17)}B @ {CAVE17:#x}")
assert len(cave17) <= 0x58
img[CAVE17-KTEXT:CAVE17-KTEXT+len(cave17)] = cave17

# entry jmp 0x9e8b7dd0 -> CAVE17
off = 0x9e8b7dd0 - KTEXT
assert bytes(img[off:off+5]) == bytes.fromhex("554889e553")
rel = CAVE17 - (0x9e8b7dd0 + 5)
img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)
print(f"cave17 -> {CAVE17:#x}, mtx_init entry jmp written")

# ---- verify no overlaps: cave13 (0x9EE30D00..D32), cave16 (D40..D54), cave15 (D60..D93), cave17 (CA8..CA8+len) ----
assert 0x9EE30D40 + 20 <= 0x9EE30D60
assert 0x9EE30D60 + 51 <= 0x9EE30DA0
print("layout: cave13 D00-D32 | cave16 D40-D54 | cave15 D60-D93 | cave17 CA8-...")

# ---- final disasm sanity ----
print("--- cave17 ---")
for i in md.disasm(cave17, CAVE17):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK caves relocated into the P5 dead body; live functions untouched")
