#!/usr/bin/env python3
"""WP12 fix #10 — allocator NULL-zone guard (crash 0x9e82b927, CR2=r14=0x180).

Crash chain (post 'Memory mode: 1: PPR16, GDDR6 16GiB', stage 49+):
  caller fn 0x9e9d7090 (per-cpu slot creator, retry loop):
      0x9e9d710e  mov rdi, [0xA1AB8440]      ; the allocator ctx — NULL cold-boot
      0x9e9d711a  call 0x9e82b880            ; Sony allocator (zone/cache alloc)
  allocator fn 0x9e82b880:
      0x9e82b8a0  mov rbx, rdi               ; rbx = zone = NULL
      0x9e82b8b8  mov eax, gs:[0x34]         ; cpu id
      0x9e82b8e0  lea r14, [rbx+rax*64+0x180]; per-cpu bucket array = 0x180
      0x9e82b927  mov r12, [r14]             ; <<< CRASH (read VA 0x180)
  [0xA1AB8440] is created by the initializer at 0x9e9d6291 (call 0x9e82b0e0
  -> mov [0xA1AB8440], rax); on our cold boot that path yields NULL.

Fix A (this script, part 1) — guard at the allocator ENTRY (protects all 17+
call sites): rdi == NULL -> immediate clean `xor eax,eax; ret` (the function's
own NULL-return contract — every caller does `test rax,rax`).
  entry 0x9e82b880: 'jmp cave7' over the first 5 prologue bytes; cave7 replays
  the displaced 17-byte prologue and jumps back to 0x9e82b891.
  cave7 @0x9EE30900 (dead ICC body, past cave6 which is now unused).

Fix B (part 2) — caller NULL-routing: 0x9e9d715b 'je 0x9e9d7170' (taken when
the saved flags arg has bit0 clear) would use r14=NULL -> 'mov [r14+0x10],rax'
-> write VA 0x10. NOP the je so the flow always falls into the designed
NULL-exit: test r14,r14; je 0x9e9d719e -> clean return (0xc, or 0 when the
slot count >= 4). Non-NULL results keep the exact original destination
(0x9e9d7170) via the nop-slide — zero behavior change for valid zones.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
CAVE7 = 0x9EE30900

ENTRY_OLD = bytes.fromhex("554889e541")  # push rbp; mov rbp,rsp; +rex prefix
assert len(ENTRY_OLD) == 5, ENTRY_OLD.hex()

# displaced prologue 0x9e82b880..0x9e82b891 (17 bytes) to replay in the cave
PROlogue = bytes.fromhex(
    "55"            # push rbp
    "4889e5"        # mov rbp, rsp
    "4157"          # push r15
    "4156"          # push r14
    "4155"          # push r13
    "4154"          # push r12
    "53"            # push rbx
    "4883ec48"      # sub rsp, 0x48
)
assert len(PROlogue) == 17

CAVE7_ASM = """
test rdi, rdi
jz nullret
push rbp
mov rbp, rsp
push r15
push r14
push r13
push r12
push rbx
sub rsp, 0x48
jmp 0x9e82b891
nullret:
xor eax, eax
ret
"""

JE_SITE = 0x9e9d715b          # '74 13' -> '90 90'
JE_OLD = bytes.fromhex("7413")
JE_NEW = bytes.fromhex("9090")

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE7_ASM, CAVE7)
cave7 = bytes(enc)
print(f"cave7: {len(cave7)} bytes @ {CAVE7:#x}")

img = bytearray(open(IMG, "rb").read())

# --- verify original bytes ---
off_e = 0x9e82b880 - KTEXT
if bytes(img[off_e:off_e + 5]) != ENTRY_OLD:
    print(f"FAIL entry: {bytes(img[off_e:off_e+5]).hex()} != {ENTRY_OLD.hex()}")
    sys.exit(1)
off_je = JE_SITE - KTEXT
if bytes(img[off_je:off_je + 2]) != JE_OLD:
    print(f"FAIL je site: {bytes(img[off_je:off_je+2]).hex()} != {JE_OLD.hex()}")
    sys.exit(1)
# sanity: the replayed prologue must equal the original 17 bytes
if bytes(img[off_e:off_e + 17]) != PROlogue:
    print(f"FAIL prologue: {bytes(img[off_e:off_e+17]).hex()} != {PROlogue.hex()}")
    sys.exit(1)
# cave7 area must be the untouched dead ICC body (same bytes as pristine base)
print(f"cave7 area old bytes: {bytes(img[CAVE7-KTEXT:CAVE7-KTEXT+16]).hex()}")

# --- fix A: entry jmp cave7 ---
rel = CAVE7 - (0x9e82b880 + 5)
jmp = b"\xe9" + rel.to_bytes(4, "little", signed=True)
img[off_e:off_e + 5] = jmp

# --- write cave7 ---
off_c7 = CAVE7 - KTEXT
img[off_c7:off_c7 + len(cave7)] = cave7

# --- fix B: NOP the caller's je ---
img[off_je:off_je + 2] = JE_NEW

# --- log ---
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- entry 0x9e82b880 ---")
for i in md.disasm(bytes(img[off_e:off_e + 17]), 0x9e82b880):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
print("--- cave7 ---")
for i in md.disasm(cave7, CAVE7):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
print("--- caller 0x9e9d7157.. ---")
for i in md.disasm(bytes(img[0x9e9d7157-KTEXT:0x9e9d7166-KTEXT]), 0x9e9d7157):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK fix #10: NULL zone -> clean NULL return; caller routes NULL to designed exit")
