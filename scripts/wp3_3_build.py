#!/usr/bin/env python3
"""WP3-STEP 3: Build the boot artifacts.
 1. kernel_raw.bin   — flat image [0x1e3f0000, 0x22224000) from the reconstructed ELF
 2. patches.inc      — nasm patch table applied by the trampoline IN MEMORY after copy:
      * 33 vmmcall sites -> xor eax,eax; nop   (hypercall shim, returns 0)
      * console un-mute  [0x9fe4c15a] 0x20 -> 0x00 (devkit mode)
      * pmap_bootstrap: force default-branch constants = live values (slot 0x18c,
        d39 0x11c, d30 0x1dc) + NOP the two param-path gates
      * Titania UART device putc -> QEMU debugcon out 0x402
      * console mute byte in .data zeroed
 3. meta.inc         — preload metadata blob (modulep page @0x22224000)
 4. params.inc       — phys param block values (reverse-extracted from live .data)
"""
import sys, struct, json, re

ELF = "./download/ps5_kernel_1360_reconstructed.elf"
OUT = "./wp3_boot"
KBASE_VA   = 0xFFFFFFFF9E3F0000
KBASE_PHYS = 0x1E3F0000
T_VA, T_OFF, T_SZ = 0x9E3F0000, 0x1000, 0xCC0000
D_VA, D_OFF, D_SZ = 0x9F0B0000, 0xCC1000, 0x3174000

blob = open(ELF, "rb").read()
def va2img(va):          # VA -> offset within flat kernel image (kernel VAs are 0xffffffff_XXXXXXXX)
    lo = va & 0xFFFFFFFF
    if 0x9E3F0000 <= lo < 0x9F0B0000:
        return lo - 0x9E3F0000
    if 0x9F0B0000 <= lo < 0xA2224000:
        return 0xCC0000 + (lo - 0x9F0B0000)
    raise ValueError(hex(va))
def img_bytes(va, n):
    o = va2img(va)
    return blob[T_OFF + o: T_OFF + o + n] if o < 0xCC0000 else blob[D_OFF + (o - 0xCC0000): D_OFF + (o - 0xCC0000) + n]

# ---------------- 1. flat kernel image ----------------
raw = blob[T_OFF:T_OFF+T_SZ] + blob[D_OFF:D_OFF+D_SZ]
assert len(raw) == T_SZ + D_SZ == 0x3E34000
open(f"{OUT}/kernel_raw.bin", "wb").write(raw)
print(f"kernel_raw.bin: {len(raw)} bytes = {len(raw)/2**20:.1f} MiB, phys [0x{KBASE_PHYS:x}, 0x{KBASE_PHYS+len(raw):x})")

# ---------------- 2. vmmcall sites ----------------
d = json.load(open("./download/ps5_wp1/wp1_1_hypercalls.json"))
sites = []
for w in d["wrappers"]:
    for line in w["disasm"].split("\n"):
        m = re.match(r"\s*(0x[0-9a-f]+)\s+([0-9a-f]+)\s+vmmcall", line)
        if m:
            s = int(m.group(1), 16)
            if s < 0x1000000000000000:      # WP1 JSON dropped one leading 'f'
                s |= 0xF000000000000000
            assert 0xFFFFFFFF9F000000 <= s < 0xFFFFFFFF9F010000, hex(s)
            sites.append(s)
sites = sorted(set(sites))
print(f"vmmcall sites: {len(sites)}")
for s in sites:
    assert img_bytes(s, 3) == bytes.fromhex("0f01d9"), hex(s)
print("all sites verified 0f01d9")

# ---------------- 3. patch table ----------------
patches = []   # (img_offset, expected_bytes, new_bytes, label)
def add(va, expect, new, label):
    off = va2img(va)
    got = img_bytes(va, len(expect))
    assert got == expect, f"{label}: expected {expect.hex()} got {got.hex()} @0x{va:x}"
    patches.append((off, expect, new, label))
    print(f"  patch {label}: img+0x{off:x} ({va:#x}) {expect.hex()} -> {new.hex()}")

print("\nboot patches:")
# 3a. hypercall shim
for s in sites:
    add(s, bytes.fromhex("0f01d9"), bytes.fromhex("31c090"), f"vmmcall@{s:#x}")

# 3b. console un-mute (config blob in .text)
add(0x9FE4C15A, bytes([0x20]), bytes([0x00]), "console-unmute")

# 3c. pmap_bootstrap gates: force default branch (NOP the two je)
add(0x9ECCC006, bytes.fromhex("7431"), bytes.fromhex("9090"), "pmap-gateA-nop")
add(0x9ECCC014, bytes.fromhex("7423"), bytes.fromhex("9090"), "pmap-gateB-nop")
# default-branch immediates -> live constants
#   mov dword [rip+rel], 0x100  @0x9eccc016  (c7 05 rel32 imm32; imm at +6+4)
for va, old, new, label in [
    (0x9ECCC016 + 6, struct.pack("<I", 0x100),  struct.pack("<I", 0x18C), "recursive-slot=0x18c"),
    (0x9ECCC020 + 6, struct.pack("<I", 0x1FE),  struct.pack("<I", 0x11C), "d39=0x11c"),
    (0x9ECCC02A + 6, struct.pack("<I", 0),      struct.pack("<I", 0x1DC), "d30=0x1dc"),
]:
    add(va, old, new, label)

# 3d. Titania UART device putc -> debugcon out 0x402
orig_putc = img_bytes(0x9E739BC0, 0x24)
new_putc = bytes.fromhex("4088f066ba0204eec3") + b"\x90" * (0x24 - 9)
add(0x9E739BC0, orig_putc, new_putc, "putc->debugcon")

# 3e. console mute byte in .data (belt&braces; also set from patched config)
add(0xA05E9598, bytes([0x20]), bytes([0x00]), "mute-data=0")

# 3e2. PSP mailbox: status register at phys 0xFDC10570 has no backing in QEMU.
#      Patch the ready-wait (js) -> unconditional jmp so commands "complete".
add(0x9E6AB4B5, bytes.fromhex("7869"), bytes.fromhex("eb69"), "psp-mbox-ready-force")
add(0x9E6AB5D3, bytes.fromhex("7477"), bytes.fromhex("eb77"), "psp-mbox-done-force")
add(0x9E6AB529, bytes.fromhex("758c"), bytes.fromhex("9090"), "psp-mbox-ready2-nop")


# 3f. live-residue globals that must be NULL at cold boot (warm-path traps).
#     Each was found empirically: the code tests NULL and takes a safe cold path.
LIVE_RESIDUE_ZERO = [
    (0xA199B098, "vm_resv/vmem ptr (0x9e94c320 guard)"),
    (0xA191B538, "static-env-present flag"),
    (0xA191B560, "kern_envp array ptr"),
    (0xA1926628, "conslog-enabled gate (printf sinks)"),
    (0x9FEB8930, "log()-enabled gate"),
]
for va, label in LIVE_RESIDUE_ZERO:
    cur = img_bytes(va, 8)
    add(va, cur, bytes(8), label + " := 0")

# ---------------- 4. emit patches.inc ----------------
with open(f"{OUT}/patches.inc", "w") as f:
    f.write("; auto-generated by wp3_3_build.py — DO NOT EDIT\n")
    f.write(f"PATCH_COUNT equ {len(patches)}\n")
    f.write("patch_table:\n")
    for off, expect, new, label in patches:
        f.write(f"    dd 0x{off:08x}          ; phys 0x{KBASE_PHYS+off:08x} — {label}\n")
        f.write(f"    dd {len(expect)}\n")
        f.write(f"    db {','.join(str(b) for b in expect)}\n")
        f.write(f"    db {','.join(str(b) for b in new)}\n")
print(f"\npatches.inc: {len(patches)} entries")

# ---------------- 5. preload metadata blob ----------------
# FreeBSD flat (type, len, data) tuples, 8-byte aligned, {0,0} terminator
def align8(n): return (n + 7) & ~7
meta = b""
def rec(t, data):
    global meta
    r = struct.pack("<II", t, len(data)) + data
    meta += r + b"\0" * (align8(len(r)) - len(r))
rec(1, b"kernel\0")                    # MODINFO_NAME
rec(2, b"elf kernel\0")                # MODINFO_TYPE
rec(3, struct.pack("<Q", len(raw)))    # MODINFO_SIZE
# MODINFOMD_SMAP = 0x9001: N * {u64 base, u64 len, u32 type}
smap_entries = [
    (0x1000,    0x9B000 - 0x1000,     1),   # low RAM (up to param block)
    (0x9C000,   0xF0000 - 0x9C000,    1),   # below BIOS area
    (0x100000,  0x40000000 - 0x100000, 1),  # main RAM (kernel carved by builder)
]
smap = b"".join(struct.pack("<QQI", b, l, t) for b, l, t in smap_entries)
rec(0x9001, smap)
meta += struct.pack("<II", 0, 0)       # terminator
assert len(meta) <= 0x1000, hex(len(meta))
with open(f"{OUT}/meta.inc", "w") as f:
    f.write("; auto-generated preload metadata (modulep @0x22224000)\n")
    f.write(f"META_LEN equ {len(meta)}\n")
    f.write("meta_blob:\n")
    for i in range(0, len(meta), 16):
        f.write(f"    db {','.join(str(b) for b in meta[i:i+16])}\n")
print(f"meta.inc: {len(meta)} bytes (SMAP: {len(smap_entries)} entries, physmem top 0x40000000)")

# ---------------- 6. phys param block ----------------
# reverse-extracted from live .data (0x9eaca400 destinations) + WP2 contract
pb = {}   # phys -> bytes
def pb_bytes(phys, data): pb[phys] = data
pb_bytes(0x9B310, bytes.fromhex("c0151b185261"))                  # 6B machine id
pb_bytes(0x9B318, b"\xff" * 6)                                    # 6B empty
pb_bytes(0x9B350, bytes.fromhex(
    "0100000000000000010000000000000022010101000000000c00000000003600200444000000000001000000000000000001000c0c0c0c008d00010000000000"))
pb_bytes(0x9B6BE, b"\x00")
pb_bytes(0x9B6C0, struct.pack("<I", 0))
pb_bytes(0x9B6D4, struct.pack("<I", 0x00010000))
pb_bytes(0x9B6D8, struct.pack("<I", 0))
pb_bytes(0x9B6DC, b"\x00")
pb_bytes(0x9B6DD, b"\x00")
pb_bytes(0x9B6E0, struct.pack("<I", 0x00120101))
pb_bytes(0x9B6E4, struct.pack("<Q", 0))
pb_bytes(0x9B6EC, struct.pack("<Q", 0))
pb_bytes(0x9BF44, bytes.fromhex("660000"))
pb_bytes(0x9BF48, struct.pack("<I", 1))
pb_bytes(0x9BF4C, struct.pack("<Q", 0))            # KERNBASE GB selector
pb_bytes(0x9BF54, struct.pack("<Q", 0x1E1E0000))   # low-mem/DMAP window base
pb_bytes(0x9BF5C, b"\x00")
pb_bytes(0x9BF6C, struct.pack("<I", 0x00070000))
pb_bytes(0x9BF70, struct.pack("<I", 0x00030000))
pb_bytes(0x9BF74, struct.pack("<I", 0x7F9D0000))
pb_bytes(0x9BF78, struct.pack("<I", 0x00610000))
pb_bytes(0x9B6F4, struct.pack("<Q", 0))            # kernel phys delta
with open(f"{OUT}/params.inc", "w") as f:
    f.write("; auto-generated phys param block\n")
    f.write(f"PARAM_COUNT equ {len(pb)}\n")
    f.write("param_table:\n")
    for phys in sorted(pb):
        data = pb[phys]
        f.write(f"    dd 0x{phys:08x}\n    dd {len(data)}\n")
        f.write(f"    db {','.join(str(b) for b in data)}\n")
print(f"params.inc: {len(pb)} entries")

print("\nDONE — build artifacts in wp3_boot/")
