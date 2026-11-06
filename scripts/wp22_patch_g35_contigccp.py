#!/usr/bin/env python3
"""WP22 G35 — THE contigmalloc(ccp) INIT DESIGNED-TOLERANCE

FRONTIER: the sysinit init (fn 0x9ea975b0, announced by its own banner
prints) that carves the 'ccp' contiguous region calls the
contigmalloc-family entry 0x9eff8910 (lowaddr 0x4000000 — the SAME
family G22's contigfree guards). On the QEMU boot the allocation
answers NULL and the error jump falls into the panic block whose
message is literally 'contigmalloc(ccp)':

    0x9ea9767f  call 0x9eff8910            ; the contigmalloc family
    0x9ea97684  mov [0xa1cf40b8], rax       ; the ccp region global
    0x9ea9768b  test rax, rax
    0x9ea9768e  je   0x9ea976a7             ; NULL -> the panic block
    0x9ea97690  mov rdi, rax
    0x9ea97693  call 0x9ecce330             ; pmap_kextract(region) [G29]
    0x9ea97698  mov [0xa1cf40c0], rax       ; the ccp phys global
    0x9ea9769f  xor eax, eax                ; <- the fn's own epilogue
    0x9ea976a1  add rsp, 0x10; pop rbp; ret
    0x9ea976a7  ... panic('contigmalloc(ccp)'); ud2

FIX — THE FN'S OWN CLEAN EPILOGUE (the designed tolerance, the exact
form this boot already tolerates for every other failed region/module
init): retarget the error jump's displacement (je 0x17 -> je 0x0f) so
the NULL result skips straight to the fn's own `xor eax,eax; add
rsp,0x10; pop rbp; ret` — the ccp region/phys globals keep their
cold-state zero, the consumers read the empty-region state, and the
march continues.
"""
import sys

KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"

S = 0x9EA9768E
OLD = bytes.fromhex("7417")     # je 0x9ea976a7 (the panic block)
NEW = bytes.fromhex("740f")     # je 0x9ea9769f (the fn's own clean epilogue)

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

off = S - KTEXT
site = bytes(img[off:off + 2])
if site == NEW:
    print(f"OK WP22-G35: jump @0x{S:X} already retargeted (idempotent)")
    sys.exit(0)
if site != OLD:
    print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}")
    sys.exit(1)

img[off:off + 2] = NEW
open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP22-G35: contigmalloc(ccp) init error jump @0x{S:X} "
      f"retargeted (je 0x17 -> je 0x0f) — the NULL allocation now takes "
      f"the fn's own clean epilogue, no panic")
