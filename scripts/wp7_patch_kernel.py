#!/usr/bin/env python3
"""WP7 v5 — final msgbuf activation.

Root cause chain (WP7 forensics):
  * COLD boot never runs the warm-boot msgbuf wrapper (0x9edf9184 family);
    it uses msgbuf_init(0x9f025030) via 0x9e8a1261 instead.
  * printf's msgbuf path is gated by byte [0xa1926628] == 1 (printf @0x9e89d5ae,
    kvprintf @0x9e89db60, x2 more). Our image bakes the flag = 1, but the
    trampoline's own "conslog-enabled gate := 0" patch zeroes it at runtime
    -> printf NEVER drains into msgbuf -> dmesg stays empty.
  * msgbufp/msgbufp2 must point at a msgbuf struct {msg_ptr, magic, size, ...}
    living in never-allocated RAM.

Fix (all baked into kernel_raw.bin, on top of v4):
  * P2/P3 (updated): msgbufp = msgbufp2 = DMAP(0x9B000) — the SMAP-hole param
    page, zeroed by the trampoline, never allocated by the kernel.
  * P10: code cave in the defused ICC-submit body (0x9ee2ff90):
      - writes the full struct at [msgbufp]: msg_ptr=DMAP(0xF00000),
        magic=0x63062, size=0x18000, seq fields 0, +0x48 flag=1
      - bzero(DMAP(0xF00000), 0x18000) via the kernel's own bzero 0x9e648ff0
      - sets the printf gate [0xa1926628] = 1 (re-enabling the msgbuf drain)
      - returns to msgbuf_init's caller (tail: also zeroes [0xa1fb8a68] as
        the original init would have done via its own paths)
  * P11: msgbuf_init entry (0x9f025030) -> jmp cave (5 bytes)
"""
import os, shutil, struct

RAW = "./wp3_boot/kernel_raw.bin"
BAK = "./wp3_boot/kernel_raw_wp6.bin"
KTEXT = 0x9E3F0000
DMAP = 0xFFFF8E7700000000
# Both struct AND buffer live inside the SMAP hole [0xF00000, 0x1000000):
# never allocated by the kernel AND never wiped (unlike the param page 0x9B000,
# which the kernel clears after consuming the loader contract).
STRUCT_PHYS = 0xF00000          # msgbuf struct at hole start
BUF_PHYS = 0xF00048             # buffer right after the 0x48-byte struct
BUF_SIZE = 0x17FB8              # rest of the 96KB (matches warm-path size math)
MAGIC = 0x63062

struct_va = DMAP + STRUCT_PHYS          # 0xffff8e770009b000
buf_va = DMAP + BUF_PHYS                # 0xffff8e770f000000

# rebuild from pristine backup
img = bytearray(open(BAK, "rb").read())
orig_len = len(img)

def off(va):
    o = (va & 0xFFFFFFFF) - KTEXT
    assert 0 <= o < len(img), hex(va)
    return o

patches = [
    ("P1 carve-store-nop", 0x9EDF9F3D, bytes.fromhex("4889351ceb1b03"), b"\x90" * 7),
    ("P2 msgbufp->DMAP(0x9B000)", 0xA1FB8A60, bytes.fromhex("b8ff2f7f7b8effff"), struct_va.to_bytes(8, "little")),
    ("P3 msgbufp2->DMAP(0x9B000)", 0xA1926620, bytes.fromhex("b8ff2f7f7b8effff"), struct_va.to_bytes(8, "little")),
    ("P5 ICC-recovery ret0", 0x9EE30CA0, bytes.fromhex("554889"), bytes.fromhex("31c0c3")),
    ("P7 ICC-submit ret0", 0x9EE2FF80, bytes.fromhex("554889"), bytes.fromhex("31c0c3")),
]

def orig_bytes(va, n):
    o = (va & 0xFFFFFFFF) - KTEXT
    return bytes(img[o:o + n])

def add_wipe(va, new_bytes, label):
    patches.append((label, va, orig_bytes(va, len(new_bytes)), new_bytes))

# GART residue wipes (6 container records, ptr array, 8 descriptor slots)
for rec in (0xA1ADDC80, 0xA1ADDC98, 0xA1ADDCB0, 0xA1ADDD88, 0xA1ADDDA0, 0xA1ADDDB8):
    new = bytearray(0x18)
    struct.pack_into("<Q", new, 8, 0xFFFFFFFF00000000 | rec)
    add_wipe(rec, bytes(new), f"P6 container {rec:#x} wipe")
add_wipe(0xA1ADD1B0, bytes(0x20), "P6 ptr-array wipe")
for k in range(8):
    add_wipe(0xA1ADD9B0 + k * 0x28, bytes(8), f"P6 descr-ptr slot {k} wipe")

# mDBG dump-walker slot-null
patches.append(("P8 dump-walker slot-null", 0x9ECB3B81,
                bytes.fromhex("488bb4c370010000"), bytes.fromhex("31f6") + b"\x90" * 6))

# ---- P10: msgbuf cold-init code cave --------------------------------------
CAVE = 0x9EE2FF90            # dead body of the defused ICC-submit fn
BZERO = 0x9E648FF0
GATE = 0xA1926628            # printf msgbuf drain gate

cave = bytearray()
cave += bytes.fromhex("55")                          # push rbp
cave += bytes.fromhex("4889e5")                      # mov rbp, rsp
cave += bytes.fromhex("4889fb")                      # mov rbx, rdi          ; rbx = struct
cave += bytes.fromhex("48b8") + struct.pack("<Q", buf_va)      # movabs rax, buf_va
cave += bytes.fromhex("488907")                      # mov [rbx], rax        ; msg_ptr
cave += bytes.fromhex("c74308") + struct.pack("<I", MAGIC)     # mov dword [rbx+8], magic
cave += bytes.fromhex("c7430c") + struct.pack("<I", BUF_SIZE)  # mov dword [rbx+0xc], size
cave += bytes.fromhex("48c7431000000000")            # mov qword [rbx+0x10], 0   ; seq
cave += bytes.fromhex("48c7431800000000")            # mov qword [rbx+0x18], 0
cave += bytes.fromhex("c7431c00000000")              # mov dword [rbx+0x1c], 0   ; seq_mod
# [rbx+0x20] = 0xffffffff (matches original fresh-init at 0x9f025148/163)
cave += bytes.fromhex("48c74320ffffffff")            # mov qword [rbx+0x20], -1
# lock area [rbx+0x28, rbx+0x48) = 0
cave += bytes.fromhex("48c7432800000000")            # mov qword [rbx+0x28], 0
cave += bytes.fromhex("48c7433000000000")            # mov qword [rbx+0x30], 0
cave += bytes.fromhex("48c7433800000000")            # mov qword [rbx+0x38], 0
cave += bytes.fromhex("48c7434000000000")            # mov qword [rbx+0x40], 0
# bzero(buf_va, BUF_SIZE) via the kernel's own bzero
cave += bytes.fromhex("48b8") + struct.pack("<Q", buf_va)      # movabs rax, buf_va
cave += bytes.fromhex("4889c7")                      # mov rdi, rax          ; rdi = buf
cave += bytes.fromhex("be") + struct.pack("<I", BUF_SIZE)      # mov esi, size
cave += bytes.fromhex("e8") + struct.pack("<i", BZERO - (CAVE + len(cave) + 5))  # call bzero
# gate = 1 : mov byte [rip+rel32], 1   (re-enable printf msgbuf drain)
rel_gate = GATE - (CAVE + len(cave) + 8)
cave += bytes.fromhex("c605") + struct.pack("<i", rel_gate) + bytes.fromhex("01")
cave += bytes.fromhex("31c0")                        # xor eax, eax
cave += bytes.fromhex("5d")                          # pop rbp
cave += bytes.fromhex("c3")                          # ret
assert len(cave) < 0x700, len(cave)
cave += b"\x90" * ((0x10 - len(cave) % 0x10) % 0x10)

patches.append(("P10 msgbuf-init cave", CAVE, orig_bytes(CAVE, len(cave)), bytes(cave)))

# P11: msgbuf_init entry -> jmp cave
rel11 = CAVE - (0x9F025030 + 5)
patches.append(("P11 msgbuf_init->cave", 0x9F025030,
                bytes.fromhex("554889e553"), bytes.fromhex("e9") + struct.pack("<i", rel11)))

# ---- P9: systematic residue wipe (unchanged, minus covered) ---------------
import re
_tr_src = open("./wp3_boot/patches.inc").read()
_tr = re.findall(r"dd (0x[0-9a-fA-F]+)[^\n]*\n\s*dd (\d+)[^\n]*\n\s*db ([0-9,]+)[^\n]*\n\s*db ([0-9,]+)", _tr_src)
covered = set()
for _l, _v, _e, _n in patches:
    covered.update(range((_v & 0xFFFFFFFF) - KTEXT, (_v & 0xFFFFFFFF) - KTEXT + len(_n)))
for _o, _l in ((int(o, 16), int(l)) for o, l, _e, _n in _tr):
    covered.update(range(_o, _o + _l))

DATA_OFF = 0xCC0000
wipes = []
o = DATA_OFF
while o <= len(img) - 8:
    q = int.from_bytes(img[o:o + 8], "little")
    if 0xFFFF8E7740000000 <= q <= 0xFFFF8E77FFFFFFFF and o not in covered:
        wipes.append(o)
    o += 8
for o in wipes:
    va = KTEXT + o
    patches.append((f"P9 residue-wipe {va:#x}", va, bytes(img[o:o + 8]), bytes(8)))
print(f"P9: {len(wipes)} residue pointers wiped")

# ---- apply ------------------------------------------------------------------
for label, va, expect, new in patches:
    o = off(va)
    got = bytes(img[o:o + len(expect)])
    assert got == expect, f"{label}: expected {expect.hex()} got {got.hex()} @VA {va:#x}"
    img[o:o + len(new)] = new

assert len(img) == orig_len
open(RAW, "wb").write(bytes(img))
print(f"applied {len(patches)} patch groups; kernel_raw.bin updated ({len(img)} bytes)")
print(f"msgbuf: struct @DMAP(0x{STRUCT_PHYS:x}) buf @DMAP(0x{BUF_PHYS:x}) size {BUF_SIZE:#x}")
