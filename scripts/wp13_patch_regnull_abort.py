#!/usr/bin/env python3
"""WP13 fix #4 — registry-create NULL-alloc abort (crash 0x9eff90e2, CR2=0x8 WRITE).

Fn 0x9eff90b0 (object registry insert, magic 0x3454f8e9):
    rdi = [0xA21CB488]  (alloc ctx — NULL on cold boot, same family as
                         [0xA1AB8440] from WP12 fix #10)
    call 0x9e82b880     -> NULL (clean, thanks to fix #10)
    mov [rbx+0x18], rax ; store NULL slot (fine)
    mov byte [rax+8], 0 ; <<< CRASH — write to VA 8
    ... lock registry (0xA21CB4A8), link obj into head (0xA21CB4B0),
        inc counters, tail-jmp mtx_unlock

Cold-boot semantics: allocation failed -> the object is NOT registered; abort
BEFORE taking the registry lock (so no unlock must happen — the function's own
epilogue tail-jumps to mtx_unlock, which we must NOT reach).

Fix: replace the 15-byte span 0x9eff90d7..0x9eff90e5
    lea r14,[rip+0x31d23ca]      ; r14 = 0xA21CB4A8 (registry lock)
    mov [rbx+0x18], rax
    mov byte [rax+8], 0
with `jmp cave10` + 10 nops.  cave10 @0x9EE30B00 (dead ICC body, clear):
    test rax,rax ; jz null_out
    movabs r14, 0xffffffffa21cb4a8   ; replay lea
    mov [rbx+0x18], rax              ; replay
    mov byte [rax+8], 0              ; replay
    jmp 0x9eff90e6
  null_out:
    pop rbx ; pop r14 ; pop rbp ; ret   ; clean abort, no unlock
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
CAVE10 = 0x9EE30B00
SPAN = 0x9eff90d7
SPAN_OLD = bytes.fromhex("4c8d35ca231d03" "48894318" "c6400800")
assert len(SPAN_OLD) == 15

CAVE10_ASM = """
test rax, rax
jz null_out
movabs r14, 0xffffffffa21cb4a8
mov qword ptr [rbx + 0x18], rax
mov byte ptr [rax + 8], 0
jmp 0x9eff90e6
null_out:
pop rbx
pop r14
pop rbp
ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE10_ASM, CAVE10)
cave10 = bytes(enc)
print(f"cave10: {len(cave10)}B @ {CAVE10:#x}")
assert len(cave10) <= 0x80

img = bytearray(open(IMG, "rb").read())
off = SPAN - KTEXT
if bytes(img[off:off+15]) != SPAN_OLD:
    print(f"FAIL span: {bytes(img[off:off+15]).hex()}"); sys.exit(1)

rel = CAVE10 - (SPAN + 5)
img[off:off+15] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * 10
off_c = CAVE10 - KTEXT
img[off_c:off_c+len(cave10)] = cave10

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- span ---")
for i in md.disasm(bytes(img[off:off+15]), SPAN):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
print("--- cave10 ---")
for i in md.disasm(cave10, CAVE10):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK WP13 fix #4: NULL alloc -> registry insert aborted cleanly (no unlock)")
