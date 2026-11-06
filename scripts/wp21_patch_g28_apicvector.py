#!/usr/bin/env python3
"""WP21 G28 — 'Couldn't find an APIC vector for IRQ 0' PANIC -> TOLERATED
          (NEW FRONTIER #2, found by verification boot #2: the march now
           passes the whole MP1 cpupstate stage — all 8 CPUs — and dies
           in the late interrupt-registration stage, just before the
           'Device configuration finished.' landmark)

ROOT CAUSE: the intr vector-registration fn 0x9e6976b0 allocates an APIC
vector for the IRQ being wired up and treats allocation failure as
fatal (the canonical FreeBSD panic):

      0x9e6976ba  movzx r14d, word [rdi + 0x2c]        ; the irq
      0x9e6976c2  cmp   r14w, 0xff
      0x9e6976c8  ja    0x9e6976e2                     ; >0xff -> legacy path
      0x9e6976ca  call  0x9e8f4ee0                     ; ioapic lookup
      0x9e6976d4  call  0x9e697ac0(rdi, esi)           ; apic vector allocate
      0x9e6976d9  test  eax, eax
      0x9e6976db  jne   0x9e697735                      ; <<< FAIL -> panic
                                                       ('Couldn't find an APIC vector for IRQ %d' + ud2)
      0x9e6976dd  ...the vector-map path; pops; tail-jmp rcx (the designed continue)
On our boot the APIC vector map is in the cold-boot state, so IRQ 0
(the timer) cannot get a vector and the registration panics.

FIX — THE LOCAL GUARD (the designed tolerance): NOP the 2-byte jne — a
failed allocation then flows into the fn's own continue path (vector-
map walk; pops; the tail-jmp continuation). The IRQ simply stays
unwired, exactly like every other designed-tolerance guard in this
kit; the kernel keeps marching toward the landmark.
"""
import sys

KTEXT = 0x9E3F0000
IMG = "./wp21_kit/wp3_boot/kernel_raw.bin"

S = 0x9E6976DB
OLD = bytes.fromhex("7558")                   # jne 0x9e697735 (panic block)
NEW = bytes.fromhex("9090")                   # nop x2 — tolerate the failed allocation

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

off = S - KTEXT
site = bytes(img[off:off+len(OLD)])
if site == NEW:
    print(f"site {S:#x} already patched (idempotent) — OK"); sys.exit(0)
if site != OLD:
    print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)

img[off:off+len(NEW)] = NEW
open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print(f"OK WP21-G28: 'Couldn't find an APIC vector for IRQ 0' panic NOPed "
      f"@0x{S:X} — the designed allocation-failure tolerance")
