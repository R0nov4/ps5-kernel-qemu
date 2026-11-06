#!/usr/bin/env python3
"""WP20 G7 — THE FPU XSAVE -> FXSAVE FALLBACK (the user's plan #7)
          (GPF 0xffffffff9eb21dfc: 'xsave ptr [rcx]' with CR4.OSXSAVE off)
          [2-byte in-place edit, no cave]

CASCADE: the march reached the FPU init SYSINIT:
    fn 0x9eb21db0 (the fpu probe/init):
    0x9eb21dcc  malloc(...) -> the save area (the bump window — OK)
    0x9eb21dd8  pushfq; pop r14           ; save IF
    0x9eb21ddb  cli; clts
    0x9eb21dde  cmp dword [0xa0d71f90], 0 ; the 'xsave available' flag
    0x9eb21de5  rcx = [0xa0d71fa0]        ; the save-area pointer
    0x9eb21dec  je 0x9eb21e01             ; ==0 -> the DESIGNED fxsave path
    0x9eb21eee  rax = [0xa0d71f98]        ; the xsave feature mask
    0x9eb21dfc  xsave [rcx]               <<< GPF: CR4.OSXSAVE not set
    0x9eb21e01  fxsave [rcx]              ; the DESIGNED fallback

  The flag (live-dump residue / a CPUID probe without the CR4.OSXSAVE
  enable on this QEMU TCG EPYC) says 'xsave', the CPU says no -> GPF.

THE USER'S FIX (verbatim): "强制跳到 fxsave 路径 0x9eb21e01" — the je at
  0x9eb21dec becomes jmp (74 13 -> eb 13): the init ALWAYS takes its
  OWN designed no-xsave path; the xsave branch becomes dead code.
  (The alternative — hw.use_xsave default 0 @0xa1d71f90 — is not
  needed; this edit is strictly smaller and local.)
"""
import sys

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

S = 0x9EB21DEC                       # je 0x9eb21e01 (2B)
FX = 0x9EB21E01                      # the designed fxsave path

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

off = S - KTEXT
site = bytes(img[off:off+2])
rel = FX - (S + 2)
OLD = b"\x74" + rel.to_bytes(1, "little", signed=True)
NEW = b"\xeb" + rel.to_bytes(1, "little", signed=True)

if site == NEW:
    print(f"site {S:#x}: already fallback (idempotent)")
    sys.exit(0)
if site != OLD:
    print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)

img[off:off+2] = NEW
open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"

print(f"OK WP20-G7: fpu xsave->fxsave fallback je->jmp @ {S:#x} "
      f"({OLD.hex()} -> {NEW.hex()}) — the designed legacy path always taken")
