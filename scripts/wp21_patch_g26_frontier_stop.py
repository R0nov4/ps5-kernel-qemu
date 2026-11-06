#!/usr/bin/env python3
"""WP21 G26 — THE DESIGNED FRONTIER STOP  ['Device configuration finished.']
          (the user's iron rule: pass done=1006, reach the landmark at
           done>=1078, STOP THERE — the 1158+ march is WP22's budget)

MECHANISM: 'Device configuration finished.' prints from the sysinit
thunk fn 0x9e7c3ef0 (reached ONLY via the sysinit-walk thunk
0x9e651860, referenced solely by the sysinit struct @0x9fea74f0):

      0x9e7c3ef0  push rbp; mov rbp,rsp
      0x9e7c3ef4  call 0x9ef0cf80                    ; stage finalize
      0x9e7c3ef9  cmp dword [0xa1978858], 0
      0x9e7c3f02  lea  rdi, "Device configuration finished.\\n"
      0x9e7c3f0b  call 0x9e64d410                    ; <<< THE LANDMARK PRINTS
      0x9e7c3f10  mov  dword [0xa1978a60], 0         ; <<< HOOK POINT (10-byte insn)
      0x9e7c3f1a  pop rbp; ret

DESIGN: after the landmark prints, the hook takes over:
  1. replay the printer's own side-effect (clear [0xa1978a60]);
  2. restore the walker's frame (pop rbp);
  3. perform the WALKER'S OWN done-stamp for this entry — r12 still
     holds &array[i] (callee-saved across the thunk call, verified:
     the printer touches only rax/rdi) — so done reaches position+1,
     i.e. the landmark's own count, matching the walker's 0x9e926333
     'mov rax,[r12]; mov dword [rax],1';
  4. park the CPU (cli; hlt) — the serial log ENDS at the landmark
     with zero crash lines, the cleanest possible WP21 terminal state.
Slot 0x9E403F00.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./wp21_kit/wp3_boot/kernel_raw.bin"

SLOT = 0x9E403F00
S = 0x9E7C3F10                          # mov dword [rip+0x2191b46], 0 (10B)
OLD = bytes.fromhex("c705461b190200000000")
GLOB = 0xFFFFFFFFA1978A60               # the replayed side-effect target
IMG_LO = 0xFFFFFFFF9FE51FB0             # sysinit struct sanity range
IMG_HI = 0xFFFFFFFFA2134000

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

C = f"""
    movabs r10, {GLOB:#x}
    mov    dword ptr [r10], 0
    pop    rbp
    mov    rax, qword ptr [r12]
    movabs r11, {IMG_LO:#x}
    cmp    rax, r11
    jb     no_stamp
    movabs r11, {IMG_HI:#x}
    cmp    rax, r11
    jae    no_stamp
    mov    dword ptr [rax], 1
no_stamp:
    cli
halt:
    hlt
    jmp    halt
"""
code = asm(C, SLOT)
assert len(code) <= 0x80, f"slot code too big: {len(code):#x}"

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

off = S - KTEXT
site = bytes(img[off:off+len(OLD)])
if site[:1] == b"\xe9":
    rel_expect = SLOT - (S + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    hooked = True
else:
    if site != OLD:
        print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
    hooked = False

off = SLOT - KTEXT
cur = bytes(img[off:off+len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    print(f"FAIL slot {SLOT:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)

img[off:off+len(code)] = code
if not hooked:
    rel = SLOT - (S + 5)
    off = S - KTEXT
    img[off:off+len(OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * 5

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP21-G26: the designed frontier stop @0x{S:X} (slot 0x{SLOT:X}) — "
      f"landmark prints, entry stamps, CPU parks; the log ends clean")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
