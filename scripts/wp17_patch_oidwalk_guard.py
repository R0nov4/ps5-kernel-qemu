#!/usr/bin/env python3
"""WP17 #8 — the OID path-walker phase-2 loop-head guard (cave68 @0x9E401C00)
         (belt & braces for any remaining residue in the OID chains).

The walker 0x9e9467c0's phase-2 loop (0x9e946a00: 'mov rdi,[rbx+0x30]'
+ 'call 0x9ec227a0' strlen) advances via 'rbx = [rbx+8]' and terminates
on NULL or the root 0xa197a5a0. A residue link (e.g. the pre-WP17#7
'kern'+8 = 4) walks rbx into a small integer -> [rbx+0x30] faults.

FIX — hook [0x9e946a00, 0x9e946a05) (5B: the 4-byte mov + the call's
first byte):
    rbx == 0 or rbx < 0x10000 (an implausible non-pointer) -> jump the
    loop's done point 0x9e946a58 (the post-loop buffer finalize — the same
    target the designed NULL terminator reaches);
    else replay 'mov rdi,[rbx+0x30]; call 0x9ec227a0' -> 0x9e946a09.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

CAVE68 = 0x9E401C00
S68, S68E = 0x9E946A00, 0x9E946A05          # mov rdi,[rbx+0x30]; [e8]... (5B)
DONE68 = 0xFFFFFFFF9E946A58                  # the post-loop finalize
CONT68 = 0xFFFFFFFF9E946A09                  # after the replayed mov+call
STRLEN = 0xFFFFFFFF9EC227A0                  # the replayed call target

OLD68 = bytes.fromhex("488b7b30e8")          # mov rdi,[rbx+0x30]; e8...

C68 = f"""
    test rbx, rbx
    jz   done
    cmp  rbx, 0x10000
    jb   done
    mov  rdi, qword ptr [rbx + 0x30]
    call {STRLEN:#x}
    jmp  {CONT68:#x}
done:
    jmp  {DONE68:#x}
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C68, CAVE68)
print(f"cave68: {len(code):#x}B @ {CAVE68:#x}  hook {S68:#x} (5B)")
assert len(code) <= 0x80

img = bytearray(open(IMG, "rb").read())

off = S68 - KTEXT
site = bytes(img[off:off+len(OLD68)])
if site[:1] == b"\xe9":
    rel_expect = CAVE68 - (S68 + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S68:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S68:#x}: already hooked to cave68 (idempotent rewrite)")
    hooked = True
else:
    if site != OLD68:
        print(f"FAIL site {S68:#x}: {site.hex()} != {OLD68.hex()}"); sys.exit(1)
    hooked = False

off = CAVE68 - KTEXT
cur = bytes(img[off:off+len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    print(f"FAIL cave {CAVE68:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)
print("site + cave assertions OK")

img[off:off+len(code)] = code
if not hooked:
    rel = CAVE68 - (S68 + 5)
    off = S68 - KTEXT
    img[off:off+5] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- cave68 (OID walk guard) ---")
for i in md.disasm(code, CAVE68):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP17#8: OID path-walker loop-head guard (cave68)")
