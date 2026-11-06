#!/usr/bin/env python3
"""WP22 G36 — THE contigmalloc(infl) INIT DESIGNED-TOLERANCE

FRONTIER: the sysinit init fn 0x9ef84a00 (reached via its tiny wrapper
0x9ef849f0: `call 0x9ef84a00; xor eax,eax; ret`) carves the 'infl'
contiguous region through the same contigmalloc-family entry
0x9eff8910 (lowaddr 0). On the QEMU boot the allocation answers NULL
and the error jump lands in the panic block whose message is literally
'contigmalloc(infl)':

    0x9ef84a33  call 0x9eff8910            ; the contigmalloc family
    0x9ef84a38  mov [0xa2173198], rax       ; the infl region global
    0x9ef84a3f  test rax, rax
    0x9ef84a42  je   0x9ef84a4a             ; NULL -> the panic block
    0x9ef84a44  add rsp, 0x10; pop rbp; ret ; <- the clean epilogue
    0x9ef84a4a  ... panic('contigmalloc(infl)'); ud2

FIX — THE FALLTHROUGH TOLERANCE (the designed skip, same family as
G35): NOP the 2-byte je (74 06 -> 90 90) so the NULL result falls
straight through into the fn's own clean epilogue — the infl region
global keeps its cold-state zero and the march continues.
"""
import sys

KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"

S = 0x9EF84A42
OLD = bytes.fromhex("7406")     # je 0x9ef84a4a (the panic block)
NEW = bytes.fromhex("9090")     # nop; nop -> fall into the clean epilogue

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

off = S - KTEXT
site = bytes(img[off:off + 2])
if site == NEW:
    print(f"OK WP22-G36: jump @0x{S:X} already NOPed (idempotent)")
    sys.exit(0)
if site != OLD:
    print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}")
    sys.exit(1)

img[off:off + 2] = NEW
open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP22-G36: contigmalloc(infl) init panic jump @0x{S:X} NOPed "
      f"(74 06 -> 90 90) — the NULL allocation falls into the fn's own "
      f"clean epilogue, no panic")
