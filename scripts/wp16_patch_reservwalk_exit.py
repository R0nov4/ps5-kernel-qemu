#!/usr/bin/env python3
"""WP16 #5 — vm_reserv walk early-exit on page-supply exhaustion
         (panic: _rw_wunlock_cookie: td_locks -32768).

ROOT CAUSE (GDB-stepped + serial):
  vm_page_startup's reservation walk (0x9e8f3d80, 16KB per iteration over
  the whole memory map) calls vm_page_alloc (0x9ef7a1a0) per page. The
  W1-bump supply (896KB / 3823 objects) exhausts -> NULL -> the designed
  NULL-continue at 0x9e8f3ef3: unlock(r13) + skip-the-block + WALK ON.
  The walk keeps iterating (~64K more times) over memory it can never
  allocate; each NULL-continue performs an UNBALANCED unlock (the lock
  was taken ONCE at 0x9e8f3e42 before the walk) -> thread0's td_locks
  decrements to -32768 -> 'panic: _rw_wunlock_cookie: td_locks -32768'.
  (The designed kernel never sees this: its page supply covers the whole
  walk, so the NULL-continue is a rare 'reservation full' event.)

FIX — cave46 @0x9E401000 replacing the NULL-continue head
  [0x9e8f3ef3, 0x9e8f3f05) (18B: mov rdi,r13; xor esi; xor edx; call
  0x9ebc4eb0; test [rbp-0x3c],1; jne 0x9e8f3f5b):
    - rax != 0 (not a NULL — the rare designed case): replay the whole
      designed NULL-continue sequence verbatim.
    - rax == 0 (the supply is exhausted): END THE WALK NOW —
      1. restore the vm_reserv counter: [0xa1d0c310] := [rbp-0x30]
         (the entry value saved at 0x9e8f3dbf — the walk-complete exit's
         balance check 'cmp rcx,[rbp-0x30]; jne abort(ud2)' must match)
      2. jump to the designed walk-complete exit 0x9e8f3f7f (unlock r13 —
         balancing the ONCE-taken lock from 0x9e8f3e42 — then the cnt
         check and the clean epilogue).
      Exactly ONE NULL is processed: no 64K-iteration runaway, no lock
      imbalance, vm_page_startup completes with the pages it got.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE46 = 0x9E401000
S46, S46E = 0x9E8F3EF3, 0x9E8F3F05          # the NULL-continue head (18B)
CNT_GLOBAL = 0xFFFFFFFFA1D0C310             # the vm_reserv counter
EXIT_PATH = 0xFFFFFFFF9E8F3F7F              # the walk-complete exit

OLD46 = bytes.fromhex(
    "4c89ef"          # mov rdi, r13
    "31f6"            # xor esi, esi
    "31d2"            # xor edx, edx
    "e8b10f2d00"      # call 0x9ebc4eb0
    "f645c401"        # test byte ptr [rbp-0x3c], 1
    "7556"            # jne 0x9e8f3f5b
)

C46 = f"""
    test rax, rax
    jnz  cont
    movabs rcx, {CNT_GLOBAL:#x}
    mov  rax, qword ptr [rbp - 0x30]
    mov  qword ptr [rcx], rax
    jmp  {EXIT_PATH:#x}
cont:
    mov  rdi, r13
    xor  esi, esi
    xor  edx, edx
    call {0xFFFFFFFF9EBC4EB0:#x}
    test byte ptr [rbp - 0x3c], 1
    jne  alt
    jmp  {0xFFFFFFFF9E8F3F05:#x}
alt:
    jmp  {0xFFFFFFFF9E8F3F5B:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C46, CAVE46)
print(f"cave46: {len(code):#x}B @ {CAVE46:#x}  hook {S46:#x} ({len(OLD46)}B)")
assert len(code) <= 0x80, "cave46 too big"

img = bytearray(open(IMG, "rb").read())

off = S46 - KTEXT
site = bytes(img[off:off+len(OLD46)])
if site[:1] == b"\xe9":
    rel_expect = CAVE46 - (S46 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S46:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S46:#x}: already hooked to cave46 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD46:
        print(f"FAIL site {S46:#x}: {site.hex()}")
        print(f"  expected: {OLD46.hex()}")
        sys.exit(1)
    hooked = False

off = CAVE46 - KTEXT
if not all(b == 0xCC for b in img[off:off+0x80]):
    print(f"FAIL cave {CAVE46:#x} not pristine CC"); sys.exit(1)
print("site + cave assertions OK")

md = Cs(CS_ARCH_X86, CS_MODE_64)
insns = list(md.disasm(code, CAVE46))
blob = code.hex()
if "48b910c3d0a1ffffffff" not in blob:
    for i in insns:
        print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
    print("FAIL: cnt-global movabs not found"); sys.exit(1)

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE46 - (S46 + 5)
    off = S46 - KTEXT
    img[off:off+len(OLD46)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD46) - 5)

print("--- cave46 ---")
for i in insns:
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP16#5: vm_reserv walk early-exit (cave46)")
