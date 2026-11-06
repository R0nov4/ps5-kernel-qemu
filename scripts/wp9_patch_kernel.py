#!/usr/bin/env python3
"""WP9 — allocator seeding + clean power-down halt + verbose sysinit.

Root causes fixed (on top of the full WP7 patch set, rebuilt from the WP6 base):

  W1  Sony carve/zone allocator returns NULL for container==NULL calls
      (freelists never populated in our VM; table residue wiped/not mapped):
        0x9ea05730 (zone alloc) -> bump allocator cave.
      Seed region: phys [0x3F000000, 0x40000000)  (16MB, DMAP-mapped flat,
      below 1GB, above physfree 0x222de000). Cursor lives in the first qword
      of the region (QEMU zero-fill => lazy init). Objects are 0x78-byte
      self-describing memory handles:
          +0x00/+0x08  list links (caller writes channel ptr here)
          +0x30        OWN PHYS (the "handle": callers do DMAP_BASE + [o+0x30])
          +0x50        state (allocator writes 1)
          +0x62        flags, +0x68 class, +0x69 domain, +0x6b index
      The AHCI path at 0x9ecd05db then does:
          rdi=[obj+0x30] -> 0x9ea92580 (16KB-gran bitmap set, real at runtime)
          [DMAP(obj->0x30)] = channel, memcpy(0xa1f38d30, DMAP+0x18, 0x58)
          -> attr-change walk 0x9ecdbbb0 on REAL page tables (was the
             user's 0x9ecdbe27 #GP: garbage PDE from stale +0x30).

  W2  bootverbose [0xa1978858] = 1  -> SYSINIT prints entry names
      (gate is at 0x9e96b200 inside the MADT/APIC enumerator runner).

  W3  Clean halt after "mDBG: Power down...": the print fn at 0x9ebdf627 etc.
      is followed by delay(1M) + a call to the broken 0x9ec0b8a0 which
      strcmp()s a stale pointer (0x9ea1d440 = strcmp, NOT wrmsr - per user).
      Patch the 5 identical sites `mov edi,0xf4240` -> `cli; hlt; jmp $-3`:
          0x9ebdf482, 0x9ebdf4d2, 0x9ebdf62c, 0x9ebe08e0, 0x9ebe0ddd
"""
import struct

RAW  = "./wp3_boot/kernel_raw.bin"
BAK  = "./wp3_boot/kernel_raw_wp6.bin"
KTEXT = 0x9E3F0000
DMAP  = 0xFFFF8E7700000000

# ---- W1 constants ----
SEED_BASE  = 0x3F000000            # cursor qword @ +0x0, bitmap @ +0x1000, objects @ +0x10000
SEED_BMP   = 0x3F001000            # 16KB-gran phys ownership bitmap (pre-init interim)
SEED_OBJ   = 0x3F010000            # first bump object
SEED_LIMIT = 0x40000000
ZONE_FN    = 0x9EA05730
CAVE2      = 0x9EE30100          # dead ICC-submit body, past P10's cave
HALT_SITES = (0x9EBDF482, 0x9EBDF4D2, 0x9EBDF62C, 0x9EBE08E0, 0x9EBE0DDD)
BOOTVERBOSE = 0xA1978858
BITMAP_PTR  = 0xA1CF3F10         # 16KB-gran bitmap base (residue -> NULL by P9)
DUMP_COPY   = 0x9F079D00         # systemdump memcpy fn (residue sub-ptr -> #GP @+0x19)

img = bytearray(open(BAK, "rb").read())
orig_len = len(img)

def off(va):
    o = (va & 0xFFFFFFFF) - KTEXT
    assert 0 <= o < len(img), hex(va)
    return o

def orig_bytes(va, n):
    return bytes(img[off(va):off(va) + n])

patches = []
def add(label, va, expect, new):
    patches.append((label, va, expect, new))

def add_dyn(label, va, new):
    """expect = current image bytes (for sites whose original content we trust)"""
    add(label, va, orig_bytes(va, len(new)), new)

# ============================================================================
# WP7 patch set (proven) — identical to wp7_patch_kernel.py
# ============================================================================
STRUCT_PHYS = 0xF00000
BUF_PHYS    = 0xF00048
BUF_SIZE    = 0x17FB8
MAGIC       = 0x63062
struct_va = DMAP + STRUCT_PHYS
buf_va    = DMAP + BUF_PHYS

add("P1 carve-store-nop", 0x9EDF9F3D, bytes.fromhex("4889351ceb1b03"), b"\x90" * 7)
add("P2 msgbufp->DMAP(0xF00000)", 0xA1FB8A60,
    bytes.fromhex("b8ff2f7f7b8effff"), struct_va.to_bytes(8, "little"))
add("P3 msgbufp2->DMAP(0xF00000)", 0xA1926620,
    bytes.fromhex("b8ff2f7f7b8effff"), struct_va.to_bytes(8, "little"))
add("P5 ICC-recovery ret0", 0x9EE30CA0, bytes.fromhex("554889"), bytes.fromhex("31c0c3"))
add("P7 ICC-submit ret0", 0x9EE2FF80, bytes.fromhex("554889"), bytes.fromhex("31c0c3"))

for rec in (0xA1ADDC80, 0xA1ADDC98, 0xA1ADDCB0, 0xA1ADDD88, 0xA1ADDDA0, 0xA1ADDDB8):
    new = bytearray(0x18)
    struct.pack_into("<Q", new, 8, 0xFFFFFFFF00000000 | rec)
    add_dyn(f"P6 container {rec:#x} wipe", rec, bytes(new))
add_dyn("P6 ptr-array wipe", 0xA1ADD1B0, bytes(0x20))
for k in range(8):
    add_dyn(f"P6 descr-ptr slot {k} wipe", 0xA1ADD9B0 + k * 0x28, bytes(8))

add("P8 dump-walker slot-null", 0x9ECB3B81,
    bytes.fromhex("488bb4c370010000"), bytes.fromhex("31f6") + b"\x90" * 6)

# P10 msgbuf cold-init cave
CAVE = 0x9EE2FF90
BZERO = 0x9E648FF0
GATE = 0xA1926628
cave = bytearray()
cave += bytes.fromhex("55")
cave += bytes.fromhex("4889e5")
cave += bytes.fromhex("4889fb")
cave += bytes.fromhex("48b8") + struct.pack("<Q", buf_va)
cave += bytes.fromhex("488907")
cave += bytes.fromhex("c74308") + struct.pack("<I", MAGIC)
cave += bytes.fromhex("c7430c") + struct.pack("<I", BUF_SIZE)
cave += bytes.fromhex("48c7431000000000")
cave += bytes.fromhex("48c7431800000000")
cave += bytes.fromhex("c7431c00000000")
cave += bytes.fromhex("48c74320ffffffff")
cave += bytes.fromhex("48c7432800000000")
cave += bytes.fromhex("48c7433000000000")
cave += bytes.fromhex("48c7433800000000")
cave += bytes.fromhex("48c7434000000000")
cave += bytes.fromhex("48b8") + struct.pack("<Q", buf_va)
cave += bytes.fromhex("4889c7")
cave += bytes.fromhex("be") + struct.pack("<I", BUF_SIZE)
cave += bytes.fromhex("e8") + struct.pack("<i", BZERO - (CAVE + len(cave) + 5))
rel_gate = GATE - (CAVE + len(cave) + 8)
cave += bytes.fromhex("c605") + struct.pack("<i", rel_gate) + bytes.fromhex("01")
cave += bytes.fromhex("31c0")
cave += bytes.fromhex("5d")
cave += bytes.fromhex("c3")
assert len(cave) < 0x700, len(cave)
cave += b"\x90" * ((0x10 - len(cave) % 0x10) % 0x10)
add_dyn("P10 msgbuf-init cave", CAVE, bytes(cave))

rel11 = CAVE - (0x9F025030 + 5)
add("P11 msgbuf_init->cave", 0x9F025030,
    bytes.fromhex("554889e553"), bytes.fromhex("e9") + struct.pack("<i", rel11))

# ============================================================================
# W1 — zone bump allocator cave
# ============================================================================
def q(v):
    return struct.pack("<Q", v)

c2 = bytearray()
lbl = {}
# pass 1: emit with placeholder offsets recorded per label
def emit(bs):
    c2.extend(bs)
    return len(c2)

start = 0
c2 += bytes.fromhex("4989f9")                     # mov r9, rdi          (domain)
c2 += bytes.fromhex("49ba") + q(DMAP + SEED_BASE) # movabs r10, &cursor
lbl["init"] = len(c2)
c2 += bytes.fromhex("498b02")                     # mov rax, [r10]
c2 += bytes.fromhex("4885c0")                     # test rax, rax
jne_alloc_at = len(c2)
c2 += b"\x75\x00"                                 # jne .alloc (patched)
c2 += bytes.fromhex("48b9") + q(SEED_OBJ)          # movabs rcx, first cursor
c2 += bytes.fromhex("f0490fb10a")                 # lock cmpxchg [r10], rcx
jne_init_at = len(c2)
c2 += b"\x75\x00"                                 # jne .init (patched)
c2 += bytes.fromhex("4889c8")                     # mov rax, rcx
lbl["alloc"] = len(c2)
c2 += bytes.fromhex("48b9") + q(SEED_LIMIT)       # movabs rcx, limit
c2 += bytes.fromhex("4839c8")                     # cmp rax, rcx
jae_fail_at = len(c2)
c2 += b"\x73\x00"                                 # jae .fail (patched)
c2 += bytes.fromhex("488d4878")                   # lea rcx, [rax+0x78]
c2 += bytes.fromhex("f0490fb10a")                 # lock cmpxchg [r10], rcx
jne_init2_at = len(c2)
c2 += b"\x75\x00"                                 # jne .init (patched)
c2 += bytes.fromhex("4989c0")                     # mov r8, rax          (phys)
c2 += bytes.fromhex("48bf") + q(DMAP)             # movabs rdi, DMAP
c2 += bytes.fromhex("4c01c7")                     # add rdi, r8
c2 += bytes.fromhex("4831c0")                     # xor eax, eax
for k in range(0x78 // 8):                        # 15 qword zero stores
    if k == 0:
        c2 += bytes.fromhex("488907")             # mov [rdi], rax
    else:
        c2 += bytes.fromhex(f"488947{k * 8:02x}") # mov [rdi+k*8], rax
c2 += bytes.fromhex("4c898730000000")             # mov [rdi+0x30], r8   (self-phys)
c2 += bytes.fromhex("44888f69000000")             # mov [rdi+0x69], r9b  (domain)
c2 += bytes.fromhex("4889f8")                     # mov rax, rdi
c2 += bytes.fromhex("c3")                         # ret
lbl["fail"] = len(c2)
c2 += bytes.fromhex("4831c0")                     # xor eax, eax
c2 += bytes.fromhex("c3")                         # ret

# patch jump rel8s
def set_rel8(at, target_lbl):
    rel = lbl[target_lbl] - (at + 2)
    assert -128 <= rel <= 127, (hex(at), rel)
    c2[at + 1] = rel & 0xFF

set_rel8(jne_alloc_at, "alloc")
set_rel8(jne_init_at, "init")
set_rel8(jae_fail_at, "fail")
set_rel8(jne_init2_at, "init")

assert CAVE2 + len(c2) < 0x9EE30CA0, "cave2 overruns into ICC-recovery"
assert CAVE2 >= CAVE + 0x80, "cave2 overlaps P10 cave"
add_dyn("W1 zone-bump cave", CAVE2, bytes(c2))

rel_w1 = CAVE2 - (ZONE_FN + 5)
add("W1 zone fn -> cave", ZONE_FN,
    bytes.fromhex("554889e541"), bytes.fromhex("e9") + struct.pack("<i", rel_w1))

# ============================================================================
# W4 — interim phys-ownership bitmap (its boot initializer runs too late for
#      SYSINIT[2]; P9 had NULLed the residue pointer -> fault @0x1f80)
# ============================================================================
add_dyn("W4 bitmap ptr -> DMAP(SEED_BMP)", BITMAP_PTR,
        (DMAP + SEED_BMP).to_bytes(8, "little"))

# ============================================================================
# W6 — global channel-list tail-slot anchor. Static residue = DMAP(0x7ade0070)
#      (phys 1.96GB, unmapped in our VM; P9-wiped -> NULL -> write to 0x0 at
#      0x9ecd069e during the AHCI-adjacent list merge). Point it at a reserved
#      qword in the seed area acting as the empty-list anchor.
# ============================================================================
LIST_TAIL = 0xA093E6A0
add_dyn("W6 list-tail anchor -> DMAP(0x3F000008)", LIST_TAIL,
        (DMAP + 0x3F000008).to_bytes(8, "little"))

# ============================================================================
# W7 — neutralize the PT-page-return path 0x9ece2400 (its only caller is
#      0x9ecd0770: releasing the loader/initrd staging DMAP(0x7fc00000)).
#      The PT-window table base [0xa1f38bb0] still holds the live-machine
#      residue 0xffffff8006e00000 -> search at 0x9ece3550 reads unmapped
#      -> fatal trap 12 @0x9ece3557 (fault 0xffffff8c06dfffe8). ret0 = skip
#      the release (PT pages leak — harmless in our VM).
# ============================================================================
PT_RETURN = 0x9ECE2400
add("W7 pt-return ret0", PT_RETURN,
    bytes.fromhex("554889e5"), bytes.fromhex("31c0c390"))

# ============================================================================
# W8 — map the DMAP's [1GB, 2GB) window. The kernel deliberately 0xFF-poisons
#      the app-region PD (PDPT[0x1DD] -> PD @ phys 0xac000, entries all
#      0xFFFFFFFFFFFFFFFF). QEMU's initrd staging lands at 0x7fd8c000 (inside
#      [1GB,2GB)); the module-reclaim attr-change walk (0x9ecdbbb0) then reads
#      a poison PDE as a phys -> non-canonical -> the USER'S trap 9 @
#      0x9ecdbe27 (rsp 0xffffffffa2228870) — byte-identical reproduced.
#      Fix: at SYSINIT[2] runner entry (0x9e96b140), rewrite the 512 PD
#      entries to real 2MB mappings: (0x40000000 + i*0x200000) | 0x1e3
#      (same flags as the [0,1GB) PD entries).
#      Hook: 6-byte prologue -> cave; cave replays prologue + jmp back.
# ============================================================================
SYSINIT2_FN = 0x9E96B140
CAVE3 = 0x9EE30200
L4CACHE_PTR = 0xA1F39018
PTMASK = 0x0000FFFFFFFFFF000

c3 = bytearray()
lbl3 = {}
# Revised W8: the kernel's [1GB,2GB) PD page landed in the VGA/BIOS hole
# (phys 0xac000 — device MMIO, writes vanish). We cannot fix that page.
# Instead: build OUR OWN PD in the seed area (real RAM), fill it with real
# 2MB mappings for [1GB,2GB), then point PDPT[0x1DD] at it and reload CR3
# (full TLB flush). The kernel's PT-walk then translates DMAP([1GB,2GB))
# through OUR page.
PD2_PHYS = 0x3F00F000            # our PD page (seed area, real RAM)

c3 += bytes.fromhex("488b05") + struct.pack("<i", 0)  # mov rax, [rip+rel32]
struct.pack_into("<i", c3, 3, L4CACHE_PTR - (CAVE3 + 7))
c3 += bytes.fromhex("4885c0")                          # test rax, rax
jz1_at = len(c3); c3 += b"\x0f\x84\x00\x00\x00\x00"    # jz done
c3 += bytes.fromhex("488b88") + struct.pack("<I", 0x11C * 8)   # mov rcx, [rax+0x8E0]
c3 += bytes.fromhex("48b8") + struct.pack("<Q", PTMASK)        # movabs rax, mask
c3 += bytes.fromhex("4821c1")                          # and rcx, rax  (PDPT phys)
jz2_at = len(c3); c3 += b"\x0f\x84\x00\x00\x00\x00"    # jz done
c3 += bytes.fromhex("48b8") + struct.pack("<Q", DMAP)  # movabs rax, DMAP
c3 += bytes.fromhex("4801c8")                          # add rax, rcx  (DMAP(PDPT))
c3 += bytes.fromhex("4889c1")                          # mov rcx, rax   (PDPT va)
# fill our PD page at DMAP(PD2_PHYS): 512 entries (0x40000000+i*0x200000)|0x1e3
c3 += bytes.fromhex("48b8") + struct.pack("<Q", DMAP + PD2_PHYS)   # movabs rax, PD2 va
c3 += bytes.fromhex("4889c7")                          # mov rdi, rax   (entry cursor)
c3 += bytes.fromhex("be") + struct.pack("<I", 0x40000000)          # mov esi, phys cursor
c3 += bytes.fromhex("4d31c0")                          # xor r8d, r8d   (counter)
lbl3["loop2"] = len(c3)
c3 += bytes.fromhex("b8") + struct.pack("<I", 0x1e3)   # mov eax, 0x1e3
c3 += bytes.fromhex("4809f0")                          # or rax, rsi
c3 += bytes.fromhex("488907")                          # mov [rdi], rax
c3 += bytes.fromhex("4881c6") + struct.pack("<I", 0x200000)      # add rsi, 0x200000
c3 += bytes.fromhex("4883c708")                        # add rdi, 8
c3 += bytes.fromhex("49ffc0")                          # inc r8
c3 += bytes.fromhex("4981f800020000")                  # cmp r8, 0x200
jb_at = len(c3); c3 += b"\x0f\x82\x00\x00\x00\x00"     # jb loop2
# update PDPT[0x1DD] = PD2_PHYS | 0x27  (flags matching PDPT[0x1DC] 0x222d9027)
c3 += bytes.fromhex("48b8") + struct.pack("<Q", PD2_PHYS | 0x27)  # movabs rax, new entry
c3 += bytes.fromhex("488981") + struct.pack("<I", 0x1DD * 8)      # mov [rcx+0xEE8], rax
# reload CR3 (full TLB flush)
c3 += bytes.fromhex("480f20d8")                        # mov rax, cr3
c3 += bytes.fromhex("480f22d8")                        # mov cr3, rax
lbl3["done"] = len(c3)
# replay the original 6-byte prologue and jump back
c3 += bytes.fromhex("55")                              # push rbp
c3 += bytes.fromhex("4889e5")                          # mov rbp, rsp
c3 += bytes.fromhex("4157")                            # push r15
c3 += bytes.fromhex("e9") + struct.pack("<i", SYSINIT2_FN + 6 - (CAVE3 + len(c3) + 5))

def set_rel32(at, target_lbl):
    rel = lbl3[target_lbl] - at - 6
    struct.pack_into("<i", c3, at + 2, rel)

set_rel32(jz1_at, "done")
set_rel32(jz2_at, "done")
set_rel32(jb_at, "loop2")

assert CAVE3 + len(c3) < 0x9EE30CA0, "cave3 overrun"
add_dyn("W8 dmap-[1G,2G)-map cave", CAVE3, bytes(c3))
add("W8 sysinit2 hook", SYSINIT2_FN,
    bytes.fromhex("554889e54157"),
    bytes.fromhex("e9") + struct.pack("<i", CAVE3 - (SYSINIT2_FN + 5)) + b"\x90")

# ============================================================================
# W9 — neutralize the DMAP attr-change WALK fn 0x9ecdbc60 (8 callers).
#      Root chain: the kernel allocates the [1GB,2GB) DMAP PD from the
#      VGA/BIOS hole (phys 0xac000 — device MMIO: writes vanish, reads 0xFF)
#      -> any walk over a [1GB,2GB) VA (QEMU ACPI tables @0x7fd8c000) reads
#      a garbage PDE -> non-canonical -> the user's trap 9 @0x9ecdbe27.
#      Cache-attribute changes are meaningless under QEMU TCG -> ret 0
#      (= success for every caller: `test eax,eax; je continue`).
# ============================================================================
ATTR_WALK = 0x9ECDBC60
add("W9 attr-walk ret0", ATTR_WALK,
    bytes.fromhex("554889e54157"), bytes.fromhex("31c0c39090"))

# ============================================================================
# W10 — ACPI table mapping. Two residue blockers:
#   a) the pmap_mapdev "preinit pool" cursor [0xa1f37e50] = live residue
#      0xffffffffa6618000 (collides with our KVA window contents). Reset it
#      to a safe KVA-window VA at phys 0xF100000?? no: 0xF10000 (the SMAP
#      hole [0xF00000,0x1000000), past the msgbuf — never kernel-allocated;
#      the pool is a pure VA window, content comes from the mapped phys).
#   b) the cached RSDT pointer [0xa1d93840] = live residue 0x7fd8e014
#      (the real machine's RSDP -> initrd-staging garbage here). Point it at
#      QEMU's REAL RSDP (phys 0xf52b0, deterministic with the bundled
#      SeaBIOS; the trampoline's rsdp corruption is NOPed out in the ELF).
# ============================================================================
PREINIT_POOL = 0xA1F37E50
RSDT_CACHE   = 0xA1D93840
add_dyn("W10a preinit pool base", PREINIT_POOL,
        (0xFFFFFFFF80F10000).to_bytes(8, "little"))
add_dyn("W10b rsdp ptr -> real QEMU RSDP", RSDT_CACHE,
        (0xF52B0).to_bytes(8, "little"))

# ============================================================================
# W5 — neutralize the systemdump copy fn (residue dump-config sub-ptr at
#      [0xa21fb420]+0x28 is garbage in our VM -> #GP at 0x9f079d19, looping
#      the dump walker 248x). ret0 = "copy done" -> walker completes ->
#      mute audio -> power down -> W3 clean halt.
# ============================================================================
add("W5 dump-copy ret0", DUMP_COPY,
    bytes.fromhex("554889e5"), bytes.fromhex("31c0c390"))

# ============================================================================
# W2 — bootverbose = 1
# ============================================================================
add_dyn("W2 bootverbose=1", BOOTVERBOSE, bytes.fromhex("01000000"))

# ============================================================================
# W3 — clean halt after "mDBG: Power down..."
# ============================================================================
for site in HALT_SITES:
    add(f"W3 halt @{site:#x}", site,
        bytes.fromhex("bf40420f00"), bytes.fromhex("faf4ebfd90"))

# ============================================================================
# P9 — systematic residue wipe (same as WP7; W-patches are added to `covered`
# before the scan so their expect-bytes stay pristine)
# ============================================================================
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
    qv = int.from_bytes(img[o:o + 8], "little")
    if 0xFFFF8E7740000000 <= qv <= 0xFFFF8E77FFFFFFFF and o not in covered:
        wipes.append(o)
    o += 8
for o in wipes:
    va = KTEXT + o
    add(f"P9 residue-wipe {va:#x}", va, bytes(img[o:o + 8]), bytes(8))
print(f"P9: {len(wipes)} residue pointers wiped")

# ============================================================================
# apply
# ============================================================================
for label, va, expect, new in patches:
    o = off(va)
    got = bytes(img[o:o + len(expect)])
    assert got == expect, f"{label}: expected {expect.hex()} got {got.hex()} @VA {va:#x}"
    img[o:o + len(new)] = new

assert len(img) == orig_len
open(RAW, "wb").write(bytes(img))
print(f"applied {len(patches)} patch groups; kernel_raw.bin updated ({len(img)} bytes)")
print(f"W1: zone 0x{ZONE_FN:x} -> cave 0x{CAVE2:x} ({len(c2)} bytes); seed [0x{SEED_BASE:x}, 0x{SEED_LIMIT:x})")
print(f"W2: bootverbose=1 @0x{BOOTVERBOSE:x}")
print(f"W3: clean halt at {', '.join(hex(s) for s in HALT_SITES)}")
