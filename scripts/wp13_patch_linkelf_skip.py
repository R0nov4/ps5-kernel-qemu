#!/usr/bin/env python3
"""WP13 fix #14 — link_elf_init NULL-file skip (panic "Can't create linker
structures for kernel" — the first DESIGNED panic, not a crash!).

link_elf_init fn 0x9ec19640 (Sony link_elf.c):
    linker_make_file("kernel", class) @0x9ec196c6 -> NULL (cold-boot malloc)
    mov [0xA197A3C8], rax            ; kernel linker_file global := NULL
    test rax, rax
    je 0x9ec198c7                     ; -> printf + panic path
    ...field init...
  clean epilogue: 0x9ec19871 (add rsp,8; pop rbx..r15; pop rbp; ret)

Fix: retarget the je (4-byte displacement) 0x9ec198c7 -> 0x9ec19871 —
the stage returns cleanly with a NULL kernel linker_file (cold-boot
semantics: no KLD subsystem; later linker users fail gracefully or get
their own guards).
"""
import sys

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SITE = 0x9ec196d5
OLD = bytes.fromhex("0f84ec010000")    # je 0x9ec198c7 (panic)
NEW = bytes.fromhex("0f8496010000")    # je 0x9ec19871 (clean epilogue)

img = bytearray(open(IMG, "rb").read())
off = SITE - KTEXT
if bytes(img[off:off+6]) != OLD:
    print(f"FAIL: {bytes(img[off:off+6]).hex()} != {OLD.hex()}"); sys.exit(1)
img[off:off+6] = NEW
open(IMG, "wb").write(img)
print(f"OK WP13 fix #14: link_elf_init NULL -> clean epilogue (je retargeted)")
