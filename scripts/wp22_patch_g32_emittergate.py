#!/usr/bin/env python3
"""WP22 G32 — THE DUMP-RECORD EMITTER DESIGNED-SKIP GATE

EVIDENCE (boot with G31): with the region pointer [0xA18EA020] zeroed,
the emitter 0x9e826300 STILL derefs [r15 + 0xF800] with r15 = NULL
(CR2 = 0xf800) — it neither null-checks r15 nor waits for the dump-init
allocator (0x9e826240) to run. The sibling readers DO null-check
(`test rdi,rdi; je skip`) and take their clean skip paths — only this
emitter trusts the pointer.

FIX — THE FUNCTION'S OWN DESIGNED ERROR PATH: the entry gate

    0x9e826300  cmp dword ptr [0xA18E9FF8], 0     ; the ready flag
    0x9e826307  je 0x9e826368                      ; == 0 -> designed skip
    ...
    0x9e826368  mov eax, 0xffffffdb ; ret          ; the designed answer

becomes UNCONDITIONAL: `je` -> `jmp` (one opcode byte, 74 -> EB). The
emitter always answers 0xffffffdb ('dump record not available') — the
exact cold-state answer the kernel itself defines; the dump framework
handles it and the march continues. G31 stays: the null-checking
readers keep their clean skips, and a later successful dump-init still
allocates a real region for everyone else.
"""
import sys

KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"

S = 0x9E826307
OLD = bytes.fromhex("745f")     # je 0x9e826368
NEW = bytes.fromhex("eb5f")     # jmp 0x9e826368 — the designed skip

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

off = S - KTEXT
site = bytes(img[off:off + 2])
if site == NEW:
    print(f"OK WP22-G32: gate @0x{S:X} already forced (idempotent)")
    sys.exit(0)
if site != OLD:
    print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)

img[off:off + 2] = NEW
open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP22-G32: dump-record emitter gate @0x{S:X} forced "
      f"(je->jmp) — always the designed 0xffffffdb skip answer")
