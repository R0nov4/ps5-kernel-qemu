#!/usr/bin/env python3
"""wp10_patch_kernel.py — WP10 patch set on top of the WP7 kernel image.

WP10 goals (user spec):
  1. Break the infinite MADT-handler-registry loop at SYSINIT[2]
     (node 0xffffffffa0fe32b0's next@+0x28 becomes self-referential at
      runtime because the PREPEND registrar 0x9e96aa60 links
      node->next = old_head = the live-dump residue head).
  2. Get the kernel past SYSINIT[2] (ACPI table walk) and as deep into
     SYSINIT[3..1235] as possible.

Patch list:
  W1a [0xa19d3b80] := 0   MADT handler-registry head (THE loop fix: with a
                          NULL cold head, the registrar links node->next=0
                          and the walker 0x9e96b140 terminates after 1 pass)
  W1b [0xa19d3bd0] := 0   prev/winner residue (cold state)
  W1c [0xa0fe32d8] := 0   MADT node next@+0x28 (enforced NULL)
  W2  [0x9ee2ffed] imm32 0 -> 4
                          P10 msgbuf cave: the embedded mutex lock word
                          ([struct+0x40]) was 0 = "locked by thread 0";
                          4 = MTX FREE (cmp rax,4 @0x9e8b7288)
  W3  0x9e945d80 := 31 c0 c3
                          allocator retry-prep -> always "cannot retry"
                          (single caller 0x9ef7a428); routes the NULL path
                          to 0x9ef7a738 -> W4 cave
  W4  0x9ef7a738 := jmp W5CAVE
                          the "graceful" NULL path originally jumped back
                          into the unchecked [r13+0x50] write (Sony asserts
                          allocation success); redirect to the boot pool
  W5  code cave @0x9ee30ca3 (dead ICC-recovery body, defused by WP7 P5)
                          BOOT NODE POOL: serves allocations of any size
                          (<= pool) from a 32-aligned bump arena in the
                          unused SMAP hole RAM [0xF18000, 0xFE0000) via the
                          1GB DMAP window; pool state at DMAP(0xFE0000).
                          Returns NULL when exhausted (callers that check
                          NULL survive; Sony's assert path is bypassed).
  (console un-mute lives in the TRAMPOLINE patches.inc: conslog := 1)
"""
import struct, sys

SRC = "./kit_build/wp3_boot/kernel_raw.bin"   # pristine WP7 image
DST = sys.argv[1] if len(sys.argv) > 1 else "./wp3_boot/kernel_raw.bin"

KTEXT = 0x9E3F0000
DMAP = 0xFFFF8E7700000000

# boot pool geometry (SMAP hole RAM, never allocated by the kernel)
POOL_START = 0xF18000          # right after the msgbuf region
POOL_END   = 0xFD8000          # bitmap takes [0xFD8000, 0xFE0000)
POOL_STATE = 0xFE0000          # {pool_next@+0, pool_end@+8}

CAVE = 0x9EE30CA3              # dead ICC-recovery body (after P5's 31 c0 c3)

img = bytearray(open(SRC, "rb").read())

def off(va):
    return (va & 0xFFFFFFFF) - KTEXT

def patch_bytes(va, data, expect=None, label=""):
    o = off(va)
    if expect is not None:
        cur = bytes(img[o:o+len(expect)])
        assert cur == expect, f"{label} {va:#x}: expected {expect.hex()}, found {cur.hex()}"
    img[o:o+len(data)] = data
    print(f"  {label:34s} {va:#x} (off {o:#x}): {data.hex()}")

def patch_qword(va, val, label=""):
    patch_bytes(va, struct.pack("<Q", val), label=label)

# ---------------------------------------------------------------- W1: loop fix
print("W1: MADT handler-registry cold state (breaks the SYSINIT[2] infinite loop)")
patch_qword(0xA19D3B80, 0, "W1a registry head := 0")
patch_qword(0xA19D3BD0, 0, "W1b prev/winner := 0")
patch_qword(0xA0FE32D8, 0, "W1c MADT node next := 0")

# ---------------------------------------------------------------- W2: msgbuf lock
print("W2: P10 cave msgbuf mutex lock word := 4 (FREE)")
patch_bytes(0x9EE2FFED, bytes.fromhex("04000000"),
            expect=bytes.fromhex("00000000"), label="W2 lock := MTX_FREE")

# ---------------------------------------------------------------- W3: retry-prep
print("W3: allocator retry-prep 0x9e945d80 -> xor eax,eax; ret")
patch_bytes(0x9E945D80, bytes.fromhex("31c0c3"),
            expect=bytes.fromhex("4863c7"), label="W3 no-retry")

# ---------------------------------------------------------------- W5: the cave
print("W5: boot node pool cave @0x9ee30ca3")
# Each allocation gets a 16KB slot: node struct at slot+0 (zeroed! the pool RAM
# holds SeaBIOS ZoneHigh leftovers), a fake EMPTY hash-table owner at slot+0x400
# (the allocator post-path looks up the node in node->x20+0xd8; buckets=NULL is
# a clean miss), and the data page at slot+0x1000 whose PHYS goes in node+0x30.
# One-time init also zeroes the phys-page bitmap at [0xFD8000, 0xFE0000).
BITMAP = 0xFD8000                      # 32KB bitmap, pages of 16KB -> covers 2GB
c = bytearray()
c += bytes.fromhex("4181ff00100000")                 # +0x00 cmp r15d, 0x1000
c += b"\x0f\x87\x00\x00\x00\x00"                    # +0x07 ja .null     (rel32)
c += bytes.fromhex("48b9") + struct.pack("<Q", DMAP + POOL_STATE)   # +0x0D movabs rcx, &pool
c += bytes.fromhex("488b4108")                       # +0x17 mov rax, [rcx+8]   (pool_end)
c += bytes.fromhex("4885c0")                         # +0x1B test rax, rax
c += b"\x75\x00"                                     # +0x1E jne .inited  (rel8)
c += bytes.fromhex("48bf") + struct.pack("<Q", DMAP + BITMAP)       # +0x20 movabs rdi, [bitmap..head)
c += bytes.fromhex("31c0")                           # +0x2A xor eax, eax
c += bytes.fromhex("b904100000")                     # +0x2C mov ecx, 0x1004     (bitmap+state+head)
c += bytes.fromhex("f348ab")                         # +0x31 rep stosq
c += bytes.fromhex("48b9") + struct.pack("<Q", DMAP + POOL_STATE)   # +0x34 movabs rcx, &pool
c += bytes.fromhex("b8") + struct.pack("<I", POOL_START)            # +0x3E mov eax, POOL_START
c += bytes.fromhex("488901")                         # +0x43 mov [rcx], rax
c += bytes.fromhex("b8") + struct.pack("<I", POOL_END)              # +0x46 mov eax, POOL_END
c += bytes.fromhex("48894108")                       # +0x4B mov [rcx+8], rax
INITED = 0x4F
c += bytes.fromhex("488b01")                         # +0x4F mov rax, [rcx]     (slot phys)
c += bytes.fromhex("483b4108")                       # +0x52 cmp rax, [rcx+8]
c += b"\x0f\x83\x00\x00\x00\x00"                    # +0x56 jae .null    (rel32)
c += bytes.fromhex("48810100400000")                 # +0x5C add qword [rcx], 0x4000
c += bytes.fromhex("48ba") + struct.pack("<Q", DMAP)                # +0x63 movabs rdx, DMAP
c += bytes.fromhex("4801c2")                         # +0x6D add rdx, rax        (node VA)
c += bytes.fromhex("4889d7")                         # +0x70 mov rdi, rdx
c += bytes.fromhex("50")                             # +0x73 push rax            (save slot phys)
c += bytes.fromhex("31c0")                           # +0x74 xor eax, eax
c += bytes.fromhex("b900020000")                     # +0x76 mov ecx, 0x200      (0x1000 bytes)
c += bytes.fromhex("f348ab")                         # +0x7B rep stosq           (zero the node area)
c += bytes.fromhex("58")                             # +0x7E pop rax
c += bytes.fromhex("488d8a00040000")                 # +0x7F lea rcx, [rdx+0x400] (fake owner)
c += bytes.fromhex("48894a20")                       # +0x86 mov [rdx+0x20], rcx
c += bytes.fromhex("488d8800100000")                 # +0x8A lea rcx, [rax+0x1000] (data phys)
c += bytes.fromhex("48894a30")                       # +0x91 mov [rdx+0x30], rcx
c += bytes.fromhex("4989d5")                         # +0x95 mov r13, rdx        (the node)
c += bytes.fromhex("4189de")                         # +0x98 mov r14d, ebx
c += bytes.fromhex("488b5dd0")                       # +0x9B mov rbx, [rbp-0x30]
c += bytes.fromhex("e9") + b"\x00\x00\x00\x00"      # +0x9F jmp 0x9ef7a45d      (rel32)
NULL_ = 0xA4
c += bytes.fromhex("4531ed")                         # +0xA4 xor r13d, r13d
c += bytes.fromhex("e9") + b"\x00\x00\x00\x00"      # +0xA7 jmp 0x9ef7a716      (rel32)
assert len(c) == 0xAC, hex(len(c))

# resolve labels
struct.pack_into("<i", c, 0x09, NULL_ - 0x0D)                   # ja .null
c[0x1F] = INITED - 0x20                                         # jne .inited
struct.pack_into("<i", c, 0x58, NULL_ - 0x5C)                   # jae .null
struct.pack_into("<i", c, 0xA0, 0x9EF7A45D - (CAVE + 0xA4))     # jmp .have-flow
struct.pack_into("<i", c, 0xA8, 0x9EF7A716 - (CAVE + 0xAC))     # jmp .null-return
patch_bytes(CAVE, bytes(c), label="W5 cave code")

# ---------------------------------------------------------------- W6: page bitmap
print("W6: phys-page bitmap base [0xa1cf3f10] := DMAP(0xFD8000) (P9-wiped, was 1.5GB DMAP)")
patch_qword(0xA1CF3F10, DMAP + BITMAP, "W6 bitmap base")

# ---------------------------------------------------------------- W7: mapping list head
print("W7: mapping-node list head [0xa093e6a0] := DMAP(0xFE0010) (P9-wiped, was 1.96GB DMAP)")
MAPLIST = 0xFE0010
patch_qword(0xA093E6A0, DMAP + MAPLIST, "W7 mapping list head")

# ---------------------------------------------------------------- W4: NULL path -> cave
print("W4: allocator NULL path 0x9ef7a738 -> jmp cave")
rel = CAVE - (0x9EF7A738 + 5)
w4 = bytes.fromhex("e9") + struct.pack("<i", rel) + b"\x90\x90\x90"
patch_bytes(0x9EF7A738, w4, expect=bytes.fromhex("4531ede904fdffff"), label="W4 jmp cave")

with open(DST, "wb") as f:
    f.write(img)
print(f"\nsaved -> {DST} ({len(img)} bytes)")
print("pool: DMAP(0xF18000..0xFE0000), state @DMAP(0xFE0000), cave @0x9ee30ca3")
