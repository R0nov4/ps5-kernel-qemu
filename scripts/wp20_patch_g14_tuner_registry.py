#!/usr/bin/env python3
"""WP20 G14 — THE WINDOW-TUNER SKIP + NAME-REGISTRY TAILQ LAZY-INIT  [NEW FRONTIER]
          [2 local guards: 1 in-place fn-head skip + 1 hand-assembled cave]

GUARD A — the dmem window-tuner sysinit skip (crash 0x9ee814a5, CR2=0x88):
  the tuner reads the contig-thunk's object global (0xA2046A90, NULL)
  and derefs +0x88 to size the capacity window; the ELSE branch re-reads
  the same NULL.  A subsystem skipped at its init gets its tuner skipped
  (the WP18 doctrine): the fn head -> xor eax,eax; ret.

GUARD B — the name-registry TAILQ lazy-init (crash 0x9eeb3e37, CR2=0x0):
  the registry's append slot G2 @0xA20B1150 is NULL because the owning
  init was skipped; the designed empty state (TAILQ_INIT: G2 = &G1
  @0xA20B1148) never ran.  The hand-assembled stub restores the designed
  invariant on first use:
      rax = [G2]; test; if zero: rax = G1; [G2] = rax   ; TAILQ_INIT
      then the designed append continues at 0x9eeb3e33.
"""
import sys
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
md = Cs(CS_ARCH_X86, CS_MODE_64)

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

# ---------------- GUARD A: the window-tuner fn-head skip (in place) -------------
S_A = 0x9EE81430
OLD_A = bytes.fromhex("554889")                 # push rbp; mov rbp,rsp
NEW_A = bytes.fromhex("31c0c3")                 # xor eax,eax; ret
off = S_A - KTEXT
site = bytes(img[off:off+3])
if site == NEW_A:
    print("OK window-tuner skip: already guarded (idempotent)")
elif site == OLD_A:
    img[off:off+3] = NEW_A
    print(f"OK window-tuner skip: fn head -> xor eax,eax; ret @ {S_A:#x}")
else:
    print(f"FAIL window-tuner {S_A:#x}: {site.hex()} != {OLD_A.hex()}"); sys.exit(1)

# ---------------- GUARD B: the name-registry TAILQ lazy-init (cave) -------------
SLOT = 0x9E403C00
SLOT64 = 0xFFFFFFFF9E403C00
S_B = 0x9EEB3E2C                                 # mov rax,[rip+0x31fd31d] (7B)
CONT_B = 0xFFFFFFFF9EEB3E33                      # mov [rbx+8], rax (designed)
G1 = 0xFFFFFFFFA20B1148                          # the list head FIRST slot
G2 = 0xFFFFFFFFA20B1150                          # the list append SLOT
OLD_B = bytes.fromhex("488b051dd31f03")
NOPS = 2                                         # 7B window - 5B hook

def rel32(src_end, dst):
    r = dst - src_end
    assert -(1 << 31) <= r < (1 << 31), "rel32 overflow"
    return struct.pack("<i", r)

off = S_B - KTEXT
site = bytes(img[off:off + 5 + NOPS])
if site[:1] == b"\xe9":
    rel_expect = SLOT - (S_B + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL registry site {S_B:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    hooked = True
else:
    if site != OLD_B:
        print(f"FAIL registry site {S_B:#x}: {site.hex()} != {OLD_B.hex()}"); sys.exit(1)
    hooked = False

stub = b""
stub += bytes.fromhex("488b05") + rel32(SLOT64 + 7, G2)     # mov rax,[G2]      (7B)
stub += bytes.fromhex("4885c0")                             # test rax,rax      (3B)
stub += bytes.fromhex("7514")                               # jnz ok            (2B)
stub += bytes.fromhex("48b8") + struct.pack("<Q", G1)       # mov rax,G1        (10B)
stub += bytes.fromhex("48a3") + struct.pack("<Q", G2)       # mov [G2],rax      (10B)
stub += bytes.fromhex("e9") + rel32(SLOT64 + len(stub) + 5, CONT_B)  # ok: jmp CONT
assert len(stub) == 0x25, f"stub size {len(stub):#x} != 0x25"

off2 = SLOT - KTEXT
cur = bytes(img[off2:off2 + len(stub)])
if not all(b == 0xCC for b in cur) and cur != stub:
    print(f"FAIL registry slot {SLOT:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)

img[off2:off2 + len(stub)] = stub
if not hooked:
    rel = SLOT - (S_B + 5)
    img[off:off + 5 + NOPS] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * NOPS

print("--- name-registry TAILQ lazy-init (slot 0x9E403C00) ---")
for i in md.disasm(stub, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print("OK WP20-G14: window-tuner skip + registry TAILQ lazy-init (2 guards)")
