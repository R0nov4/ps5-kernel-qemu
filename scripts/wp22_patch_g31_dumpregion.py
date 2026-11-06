#!/usr/bin/env python3
"""WP22 G31 v3 — THE DUMP-REGION SCRATCH POINTER (the DMAP form — FINAL)

EVIDENCE CHAIN (v1 zero -> v2 KVA scratch -> v3 DMAP scratch — each form
found by its own frontier boot):
  v1 (zero):   the dump framework's NULL-unchecked readers traded the
               residual garbage derefs for NULL derefs (CR2 = 0x8000 at
               the record copier, CR2 = 0xf800 at the emitter) — G32
               gated the emitter, but the copier family still faulted.
  v2 (KVA):    [0xA18EA020] = 0xFFFFFFFFBFE00000 (KVA of phys
               0x3FE00000, the SMAP-reserved window top) — the record
               copies began working, but the region's later consumers
               still hit edge behavior reading through the KVA window.
  v3 (DMAP):   [0xA18EA020] = 0xFFFF8E7740000000 = DMAP(phys 0x40000000)
               — a plain 2MB DMAP page: uniformly mapped for every
               consumer (the kextract(0x9ecce330) phys computations of
               the region-init family walk it cleanly through the G29v2
               software walk), zeroed pristine RAM, and OUTSIDE the G22
               bump window [0xffff8e773f000000, 0xffff8e7740000000) so
               the bump allocator never hands it out.

THE REAL-HW MODEL (unchanged since v1): on a real PS5 the Sony loader
PRE-SETS this global to a pre-mapped hardware dump region; the init fn
0x9e826240 then skips its own contigmalloc entirely
(`cmp [0xA18EA020],0; jne skip`). v3 is the faithful preload in its
final, boot-verified DMAP form.

Verified by the final WP22 verification boot (the delivered serial.log:
the record-copy family completes, the sbl/gbase module stages print,
'Device configuration finished.' lands at line 1384 and the log parks).

Accepts as OLD: the original residual 0xffffff8098bdc000, the v1 zero,
the v2 KVA scratch, or the v3 DMAP value itself (idempotent).
"""
import sys

KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"

G = 0xA18EA020
RESID = bytes.fromhex("00c0bd9880ffffff")   # 0xffffff8098bdc000 (LE)
ZERO = bytes.fromhex("0000000000000000")
V2 = bytes.fromhex("00e0febfffffffff")     # 0xffffffffbfe00000 (LE)
NEW = bytes.fromhex("00000040778effff")     # 0xffff8e7740000000 (LE)

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

off = G - KTEXT
site = bytes(img[off:off + 8])
if site == NEW:
    print(f"OK WP22-G31v3: [{G:#x}] already the DMAP scratch (idempotent)")
    sys.exit(0)
if site not in (RESID, ZERO, V2):
    print(f"FAIL [{G:#x}]: {site.hex()} not residual/zero/v2/v3")
    sys.exit(1)

img[off:off + 8] = NEW
open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP22-G31v3: dump-region pointer [{G:#x}] -> 0xFFFF8E7740000000 "
      f"(DMAP of phys 0x40000000 — outside the G22 bump window, mapped, "
      f"zeroed, never allocated) — the faithful Sony-preload emulation, "
      f"final boot-verified form")
