#!/usr/bin/env python3
"""WP13 fix #15 — linker-sysinit NULL-file skip (crash 0x9e943788, CR2=0x0 READ).

The linker-subsystem SYSINIT fn 0x9e943590 registers linker classes (ran
fine — static), then processes the KERNEL linker_file's symbol tables:
    0x9e94377a  mov r14, [0xA197A3C8]     ; kernel linker_file — NULL (fix #14)
    0x9e943781  lea r13, 0xA0930CA0       ; class descriptor
    0x9e943788  mov rcx, [r14]            ; <<< CRASH
    ...symbol table walk (moot without a kernel linker_file)...

Fix: NULL linker_file -> jump to the function epilogue 0x9e9440e4
(add rsp,0x58; pop rbx..r15; pop rbp; ret) — stage returns cleanly.

  span 0x9e94377a..0x9e94378a (17B) ->
      mov r14,[rip+0x3036c47]   (kept)
      test r14,r4               (new)
      je 0x9e9440e4             (new)
      nop                       (pad)
"""
import sys

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
SPAN = 0x9e94377a
OLD = bytes.fromhex(
    "4c8b35476c0303"   # mov r14, [rip+0x3036c47] -> 0xa197a3c8
    "4c8d2d18d5fe01"   # lea r13, [rip+0x1fed518] -> 0xa0930ca0
    "498b0e"           # mov rcx, [r14]
)
assert len(OLD) == 17
NEW = bytes.fromhex(
    "4c8b35476c0303"   # mov r14, [rip+0x3036c47]  (kept)
    "4c85f6"           # test r14, r14
    "0f845a090000"     # je 0x9e9440e4  (epilogue)
    "90"               # nop pad
)
assert len(NEW) == 17

# verify je target arithmetic
tgt = 0x9e943784 + 6 + 0x95a
assert tgt == 0x9e9440e4, hex(tgt)

img = bytearray(open(IMG, "rb").read())
off = SPAN - KTEXT
if bytes(img[off:off+17]) != OLD:
    print(f"FAIL: {bytes(img[off:off+17]).hex()}"); sys.exit(1)
img[off:off+17] = NEW
open(IMG, "wb").write(img)
print("OK WP13 fix #15: NULL kernel linker_file -> symbol stage returns cleanly")
