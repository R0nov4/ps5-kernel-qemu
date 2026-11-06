#!/usr/bin/env python3
"""WP23 G39 — THE UNPARK: disarm the G26 frontier stop.

The golden WP22 image parks at the landmark ('Device configuration
finished.', sysinit position 1141) via the G26 hook: the 10-byte
instruction at 0x9E7C3F10 inside the sysinit thunk 0x9e7c3ef0 was
replaced by 'jmp 0x9E403F00' (E9 rel32 + 5x NOP); the slot stub
cleared the printer side-effect global, stamped the walker's done
bit for the landmark entry and parked the CPU (cli; hlt).

G39 restores the ORIGINAL 10 bytes
    c7 05 46 1b 19 02 00 00 00 00
    mov dword [rip + 0x2191b46], 0        ; -> 0xffffffffa0955a60
so after the landmark prints, the thunk falls into its own
'pop rbp; ret' (0x9e7c3f1a) and the mi_startup walker (done-stamp
loop 0x9e926333) marches on into the 95 post-landmark entries
(1141..1235). The G26 slot code at 0x9E403F00 stays in place as
dead code — nothing jumps there after the unpark. Idempotent.
"""
import sys

KTEXT = 0x9E3F0000
IMG = "wp3_boot/kernel_raw.bin"

S = 0x9E7C3F10                           # the hooked 10-byte insn
OLD = bytes.fromhex("c705461b190200000000")
G26_SLOT = 0x9E403F00

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)}"

off = S - KTEXT
site = bytes(img[off:off + 10])

if site == OLD:
    print(f"OK WP23-G39: site {S:#x} already original — no-op")
    sys.exit(0)
if site[:1] != b"\xe9":
    print(f"FAIL site {S:#x} not the G26 hook: {site.hex()}"); sys.exit(1)
rel = int.from_bytes(site[1:5], "little", signed=True)
if S + 5 + rel != G26_SLOT:
    print(f"FAIL site {S:#x} hooked elsewhere (-> {S + 5 + rel:#x})")
    sys.exit(1)
if site[5:] != b"\x90" * 5:
    print(f"FAIL site {S:#x} tail not NOPs: {site.hex()}"); sys.exit(1)

img[off:off + 10] = OLD
open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)
for ins in md.disasm(OLD, S):
    extra = ""
    if "rip" in ins.op_str:
        d = int(ins.op_str.split("rip + ")[1].split("]")[0], 16)
        extra = f"   ; -> {ins.address + ins.size + d:#x}"
    print(f"OK WP23-G39: G26 park disarmed @0x{S:X} — "
          f"restored '{ins.mnemonic} {ins.op_str}'{extra}")
    break
