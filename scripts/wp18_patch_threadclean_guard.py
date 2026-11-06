#!/usr/bin/env python3
"""WP18 #21 — the cpu_thread_clean NULL-PCB guard (slot @0x9E402880)
          (crash 0xffffffff9ee40ffd, CR2=0x118 READ).

CASCADE (GDB wp18_gdb_c8): the kproc-failure unwind (0x9ed15b17 ->
  0x9ef80a4f -> 0x9ef80908 -> 0x9ef809cc) tears the half-created thread
  down: the recycle fn 0x9ef809a0 releases [obj+0x60], zeroes it, then
  calls cpu_thread_clean(0x9ee40ff0)(thread):
    0x9ee40ff6  rbx = [rdi+0x3f8]     ; the thread's PCB — NULL on this
                                       ; boot (the WP16 [td+0x3f8] family:
                                       ; the reconstructed threads carry
                                       ; no PCB)
    0x9ee40ffd  rsi = [rbx+0x118]     ; the PCB's FPU save area <<< CR2=0x118
    0x9ee41004  test rsi,rsi; je 0x9ee41028   ; the designed no-area skip
    ... fpu_area_free([0x9fed8b10] arena, rsi, 0x8000); [rbx+0x118] = 0 ...
    0x9ee41028  add rsp,8; pop rbx; pop rbp; ret

FIX — the LOCAL GUARD: hook [0x9ee40ffd, 0x9ee41004) (7B 'mov
  rsi,[rbx+0x118]'):
    rbx == 0  -> jmp the fn's own exit 0x9ee41028 (no PCB -> no FPU
                 state to release);
    rbx != 0  -> replay the load; jmp 0x9ee41004 (the designed flow).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E402880
S = 0x9EE40FFD                       # mov rsi,[rbx+0x118] (7B)
CONT = 0xFFFFFFFF9EE41004            # test rsi,rsi
EXIT = 0xFFFFFFFF9EE41028            # add rsp,8; pop rbx; pop rbp; ret

OLD = bytes.fromhex("488bb318010000")

C = f"""
    test rbx, rbx
    jz   nopcb
    mov  rsi, qword ptr [rbx + 0x118]
    jmp  {CONT:#x}
nopcb:
    jmp  {EXIT:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C, SLOT)
print(f"slot 0x{SLOT:x}: {len(code):#x}B  hook {S:#x} ({len(OLD)}B)")
assert len(code) <= 0x80

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

off = S - KTEXT
site = bytes(img[off:off+len(OLD)])
if site[:1] == b"\xe9":
    rel_expect = SLOT - (S + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S:#x}: already hooked to slot {SLOT:#x} (idempotent rewrite)")
    hooked = True
else:
    if site != OLD:
        print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
    hooked = False

off = SLOT - KTEXT
cur = bytes(img[off:off+len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    print(f"FAIL slot {SLOT:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)
print("site + slot assertions OK")

img[off:off+len(code)] = code
if not hooked:
    rel = SLOT - (S + 5)
    off = S - KTEXT
    img[off:off+len(OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD) - 5)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cpu_thread_clean NULL-PCB guard (slot 0x9E402880) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#21: cpu_thread_clean NULL-PCB guard (local guard @0x9E402880)")
