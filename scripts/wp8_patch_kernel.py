#!/usr/bin/env python3
"""WP8 — AHCI allocator defuse + systemdump stabilization + verbose boot.

WP8 forensics (all GDB-verified on the local QEMU boot):
  * Crash 1 (trap 12, 0x9ef7a475, fault va 0x50): Sony allocator fn 0x9ef7a1a0.
    - Executed during SYSINIT stage #2 of 1235 (struct 0x9fec8e20, order=1,
      func thunk 0x9e652900 -> 0x9e96b140 = driver-attach sweep dispatcher).
      First driver node 0xa0fe32b0 = AHCI -> attach 0x9ef918e0 -> channel init
      -> allocator(NULL, NULL, 0x120).
    - Refill path fails (profile[0] @ 0xa1925ea0 is all-zero EVEN in the
      pristine live dump — P9 is NOT the culprit), r13 = NULL falls into the
      shared success-stamp `mov [r13+0x50], rax` -> page fault.
    - Caller 0x9ecd05db DOES check NULL (`test rax,rax; jne`) and has a
      fallback allocator (0x9ece27d0). So a clean NULL return is handled.
    - FIX W1: NULL-guard in front of the stamp (14 bytes @ 0x9ef7a467):
      `test r13,r13; je 0x9ef7a716` (clean NULL-return epilogue). The dropped
      `cmp byte [0xa1cf2fcc],0 / call 0x9ef7a7b0` never fired (flag == 0 in
      the image) — zero behavior change. Guards ALL failure entry paths.
  * Crash 2 (trap 9 x248, 0x9f079d19, systemdump writer): fn 0x9f079d00 reads
    stale residue [0xa21fb420] -> garbage ptr -> GPF on `add rsi,[rax+0x10]`.
    - FIX W2: `xor eax,eax; ret` at entry (fn returns 0 naturally anyway).
  * Crash 3 (trap 12 x117, 0x9ee3109b, nested dump loop): fn 0x9ee31090 sets
    [state+0x1088]=rdi where state = [0xa1fdf3c0] gets freed+NULLed between
    dump iterations.
    - FIX W3: NULL-guard (24-byte rewrite keeps the setter when state valid).
  * FIX W4: bootverbose := 1 @ 0xa1978858 (runtime-verified 0) so drivers
    log verbosely during SYSINIT.

P9 policy: pass "keep-p9" to keep the WP7 965-pointer blind wipe, otherwise
P9 is REMOVED per user directive (targeted patches only). P6 (GART wipes)
stays either way.

Usage: python3 wp8_patch_kernel.py [keep-p9|no-p9]   (default: no-p9)
"""
import os, shutil, struct, re, sys

RAW = "./wp3_boot/kernel_raw.bin"
BAK = "./wp3_boot/kernel_raw_wp6.bin"
KTEXT = 0x9E3F0000
DMAP = 0xFFFF8E7700000000
# Both struct AND buffer live inside the SMAP hole [0xF00000, 0x1000000):
# never allocated by the kernel AND never wiped.
STRUCT_PHYS = 0xF00000          # msgbuf struct at hole start
BUF_PHYS = 0xF00048             # buffer right after the 0x48-byte struct
BUF_SIZE = 0x17FB8              # rest of the 96KB (matches warm-path size math)
MAGIC = 0x63062

struct_va = DMAP + STRUCT_PHYS
buf_va = DMAP + BUF_PHYS

KEEP_P9 = len(sys.argv) > 1 and sys.argv[1] == "keep-p9"

# rebuild from pristine backup
img = bytearray(open(BAK, "rb").read())
orig_len = len(img)

def off(va):
    o = (va & 0xFFFFFFFF) - KTEXT
    assert 0 <= o < len(img), hex(va)
    return o

patches = [
    ("P1 carve-store-nop", 0x9EDF9F3D, bytes.fromhex("4889351ceb1b03"), b"\x90" * 7),
    ("P2 msgbufp->DMAP(0xF00000)", 0xA1FB8A60, bytes.fromhex("b8ff2f7f7b8effff"), struct_va.to_bytes(8, "little")),
    ("P3 msgbufp2->DMAP(0xF00000)", 0xA1926620, bytes.fromhex("b8ff2f7f7b8effff"), struct_va.to_bytes(8, "little")),
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

# ---- W1: allocator stamp NULL-guard ----------------------------------------
# orig @ 0x9ef7a467: cmp byte [0xa1cf2fcc],0 ; je +5 ; call 0x9ef7a7b0
# new : test r13,r13 ; je 0x9ef7a3ea ; nop*5
#   0x9ef7a3ea = the failure exit that FIRST releases the profiles lock
#   (call unlock @0x9ef7a3fa) then returns r13 = NULL. Jumping straight to
#   the epilogue (0x9ef7a716) would LEAK the lock -> td_locks imbalance ->
#   "panic: __mtx_unlock_flags: td_locks -32768".
#   The dropped `call 0x9ef7a7b0` never fired (flag [0xa1cf2fcc] == 0).
patches.append(("W1 alloc stamp null-guard", 0x9EF7A467,
                bytes.fromhex("803d5e8bd702007405e83b030000"),
                bytes.fromhex("4d85ed0f847affffff9090909090")))

# ---- W2: systemdump writer defuse (trap-9 site) -----------------------------
patches.append(("W2 dump-writer ret0", 0x9F079D00,
                bytes.fromhex("554889"), bytes.fromhex("31c0c3")))

# ---- W3: dump-state setter NULL-guard (trap-12 site) ------------------------
# orig @ 0x9ee3109b: mov [rax+0x1088],rdi ; mfence ; mov rax,[0xa1fdf3c0] ;
#                    mov byte [rax+0x1084],1
# new : test rax,rax ; je pop+ret ; mov [rax+0x1088],rdi ; mfence ;
#       mov byte [rax+0x1084],1 ; nop*2
patches.append(("W3 dump-setter null-guard", 0x9EE3109B,
                bytes.fromhex("4889b8881000000faef0488b0514e31a03c6808410000001"),
                bytes.fromhex("4885c074134889b8881000000faef0c68084100000019090")))

# ---- W4: bootverbose := 1 ----------------------------------------------------
patches.append(("W4 bootverbose=1", 0xA1978858, b"\x00", b"\x01"))

# ---- W5: mDBG event-logger stale object ptr -> NULL ---------------------------
# Crash 0x9ebe0043: r15 = [0xa1979e80] = DMAP(0x7997d9e0) (live residue, >1GB).
# The kernel's own NULL check at 0x9ebe0033 then skips event logging cleanly.
patches.append(("W5 mDBG evlog stale-ptr null", 0xA1979E80,
                (0xFFFF8E777997D9E0).to_bytes(8, "little"), bytes(8)))

# ---- W6: fallback-allocator zone list head -> NULL ----------------------------
# Crash 0x9ece2944: r14 = [0xa093e698] = DMAP(0x3410000) — in-1GB residue ptr,
# but the object at phys 0x3410000 is zeroed QEMU RAM -> [r14+0x78]=0 -> [0].
# NULL makes the fallback skip its zone walk (je 0x9ece331f = lock release).
patches.append(("W6 fallback zone head null", 0xA093E698,
                (0xFFFF8E7703410000).to_bytes(8, "little"), bytes(8)))

# ---- W8: AHCI chan-alloc retry loop -> give up after first failure ------------
# With profiles empty the Sony carve allocator + zone fallback both return NULL
# forever; the caller's "wait for memory" retry loop (0x9ecd0536) spins
# indefinitely (GDB: RIP cycling the two allocator mutex locks). Redirect the
# loop-back `je 0x9ecd0536` to the natural give-up/cleanup exit 0x9ecd0669 so
# the attach aborts cleanly and the driver sweep continues.
patches.append(("W8 chan-alloc give-up", 0x9ECD05F4,
                bytes.fromhex("0f843cffffff"),
                bytes.fromhex("e970000000") + b"\x90"))

# ---- W9: skip release-bookkeeping of never-allocated memory -------------------
# After W8 the give-up path calls 0x9ece2400 (zone-release bookkeeping) which
# walks a residue table base [0xa1f38bb0] = 0xffffff8006e00000 -> walker fn
# 0x9ece3550 faults at garbage 0xffffff8c06dfffe8. The block was never
# allocated, so the release is meaningless — NOP the call site (5 bytes).
patches.append(("W9 skip bogus release", 0x9ECD0770,
                bytes.fromhex("e88b1c0100"), b"\x90" * 5))

# ---- W7: GART segment-state records (second cluster) --------------------------
# Crash 0x9ea05bd6: TAILQ_REMOVE-style helper unlinking node 0xffff8e775eed8528
# taken from a 1-element live-residue TAILQ at 0xa1addec0/c8 (count @ +0x10=1),
# plus the segment base ptr at 0xa1adde80. Zero the three stale qwords
# (count fields stay — matches what P9 did, keep-p9 boots past this point).
for va, val in ((0xA1ADDE80, 0xFFFF8E775EED8000),
                (0xA1ADDEC0, 0xFFFF8E775EED8528),
                (0xA1ADDEC8, 0xFFFF8E775EED8528)):
    patches.append((f"W7 gart-rec stale-ptr {va:#x}", va,
                    val.to_bytes(8, "little"), bytes(8)))

# ---- P9: systematic residue wipe (optional) ---------------------------------
if KEEP_P9:
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
    print(f"P9: {len(wipes)} residue pointers wiped (KEPT)")
else:
    print("P9: REMOVED (blind wipe disabled — targeted patches only)")

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
print(f"W1 allocator guard / W2 dump-writer ret0 / W3 dump-setter guard / W4 bootverbose=1")
