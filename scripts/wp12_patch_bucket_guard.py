#!/usr/bin/env python3
"""WP12 fix #5 — hash-lookup bucket guard (CR2=0x4 @0x9e9467ee).

After the DMAP-low residue wipe (fix #4), some static-table zone entries
still carry garbage bucket fields ([arg+8] = 4, NULL, or other non-canonical
values).  hash-lookup 0x9e9467c0 dereferences the bucket three times
(first @0x9e9467ee, insert-walk @0x9e94685c, head-insert @0x9e9469ae),
so any garbage value crashes.

Guard INSIDE the function (protects every caller):
  - bucket non-canonical  -> immediate clean return 0 (rax=0) via the
    function's own epilogue 0x9e946cd6; the outer table-walk ignores the
    return value (call; jmp next-entry), so registration is simply skipped
    for residue entries — cold-boot semantics.
  - bucket canonical, first==NULL -> original not-found path 0x9e94682d.
  - bucket canonical, first!=NULL -> original flow at 0x9e9467f6.

In-place: 0x9e9467ea..0x9e9467f5 (12 bytes) -> jmp cave4 + 7 nops.
cave4 @0x9EE30600 (dead ICC body, past cave3 which ends at 0x9EE3050E).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
CAVE4 = 0x9EE30600

SPAN_OLD = bytes.fromhex(
    "4c8b7f08"   # mov r15,[rdi+8]
    "498b1f"     # mov rbx,[r15]
    "4885db"     # test rbx,rbx
    "7437"       # je 0x9e94682d
)
assert len(SPAN_OLD) == 12

CAVE4_ASM = """
mov r15, qword ptr [rdi + 8]
movabs rax, 0xffff000000000000
cmp r15, rax
jb bad
mov rbx, qword ptr [r15]
test rbx, rbx
je 0x9e94682d
jmp 0x9e9467f6
bad:
xor eax, eax
jmp 0x9e946cd6
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(CAVE4_ASM, CAVE4)
cave4 = bytes(enc)
print(f"cave4: {len(cave4)} bytes @ {CAVE4:#x}")

img = bytearray(open(IMG, "rb").read())

off = 0x9e9467ea - KTEXT
cur = bytes(img[off:off + 12])
if cur != SPAN_OLD:
    print(f"FAIL span: {cur.hex()} != {SPAN_OLD.hex()}")
    sys.exit(1)

# write the jmp + nops
rel = CAVE4 - (0x9e9467ea + 5)
jmp = b"\xe9" + rel.to_bytes(4, "little", signed=True)
img[off:off + 12] = jmp + b"\x90" * 7

# write cave4
off_c4 = CAVE4 - KTEXT
print(f"cave4 area old bytes: {bytes(img[off_c4:off_c4+16]).hex()}")
img[off_c4:off_c4 + len(cave4)] = cave4

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- site ---")
for i in md.disasm(bytes(img[off:off + 12]), 0x9e9467ea):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
print("--- cave4 ---")
for i in md.disasm(cave4, CAVE4):
    print(f"  {i.address:#x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
print("OK hash-lookup bucket guard: non-canonical bucket -> clean return 0")
