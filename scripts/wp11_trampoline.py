#!/usr/bin/env python3
"""WP11 Phase A/B — trampoline.elf analysis.
Parse ELF32 phdrs, locate the baked patch_table (676 entries), verify the
conslog-gate entry, check overlaps vs W-sites, and disassemble the two
rsdp_scan call sites (VA 0x103E8D / 0x103E9C).
"""
import struct
import capstone

ELF_PATH = "./kit_build/wp3_boot/trampoline.elf"
elf = open(ELF_PATH, "rb").read()
KTEXT = 0x9E3F0000
md32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

assert elf[:4] == b"\x7fELF" and elf[4] == 1, "not ELF32"
e_entry, = struct.unpack_from("<I", elf, 0x18)
e_phoff, = struct.unpack_from("<I", elf, 0x1C)
e_phentsize, e_phnum = struct.unpack_from("<HH", elf, 0x2A)
print(f"ELF32 entry={e_entry:#x} phoff={e_phoff:#x} phentsize={e_phentsize} phnum={e_phnum}")

segs = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
        struct.unpack_from("<IIIIIIII", elf, o)
    if p_type == 1:
        segs.append((p_offset, p_vaddr, p_paddr, p_filesz, p_memsz))
        print(f"  LOAD off={p_offset:#x} vaddr={p_vaddr:#x} paddr={p_paddr:#x} filesz={p_filesz:#x} memsz={p_memsz:#x}")

def va2file(va):
    for off, vaddr, paddr, fsz, msz in segs:
        if vaddr <= va < vaddr + fsz:
            return off + (va - vaddr)
    return None

# ---- locate baked patch_table: first entry pattern ----
first = struct.pack("<II", 0x00C16A19, 3) + bytes([15, 1, 217]) + bytes([49, 192, 144])
pos = elf.find(first)
assert pos >= 0, "patch_table first entry not found"
print(f"\npatch_table baked @ file {pos:#x}")

# walk 676 entries
entries = []
p = pos
for n in range(676):
    off, ln = struct.unpack_from("<II", elf, p)
    expect = elf[p + 8:p + 8 + ln]
    new = elf[p + 8 + ln:p + 8 + 2 * ln]
    entries.append((off, ln, expect, new))
    p += 8 + 2 * ln
print(f"parsed {len(entries)} entries, table ends @ file {p:#x}")

# gate check
for off, ln, expect, new in entries:
    if off == 0x03536628:
        print(f"GATE entry: off={off:#x} len={ln} expect={expect.hex()} new={new.hex()}  (new==0: {new == bytes(ln)})")

# overlap check vs all W-patch sites
SITES = {
    "W1 hook 0x9ea05730": (0x9EA05730, 5),
    "W1 cave 0x9ee30100": (0x9EE30100, 0x60),
    "W8 cave 0x9ee30200": (0x9EE30200, 0xA0),
    "W8 hook 0x9e96b140": (0x9E96B140, 6),
    "W3a 0x9ebdf482": (0x9EBDF482, 5), "W3b 0x9ebdf4d2": (0x9EBDF4D2, 5),
    "W3c 0x9ebdf62c": (0x9EBDF62C, 5), "W3d 0x9ebe08e0": (0x9EBE08E0, 5),
    "W3e 0x9ebe0ddd": (0x9EBE0DDD, 5),
    "W5 0x9f079d00": (0x9F079D00, 4), "W7 0x9ece2400": (0x9ECE2400, 4),
    "W9 0x9ecdbc60": (0x9ECDBC60, 5),
    "MADT 0xa19d3b80": (0xA19D3B80, 8), "MADT 0xa19d3bd0": (0xA19D3BD0, 8),
    "MADT 0xa0fe32d8": (0xA0FE32D8, 8),
    "RSDP 0xa1d93840": (0xA1D93840, 8), "POOL 0xa1f37e50": (0xA1F37E50, 8),
    "BOOTVB 0xa1978858": (0xA1978858, 8),
    "BITMAP 0xa1cf3f10": (0xA1CF3F10, 8), "LISTTAIL 0xa093e6a0": (0xA093E6A0, 8),
}
bad = 0
for name, (va, sz) in SITES.items():
    o = va - KTEXT
    hits = [(hex(eoff), ln) for eoff, ln, _, _ in entries
            if not (eoff + ln <= o or eoff >= o + sz)]
    if hits:
        bad += 1
        print(f"  !! OVERLAP {name}: {hits}")
print(f"overlap check done, {bad} conflicts")

# ---- rsdp_scan call sites ----
print("\n=== rsdp_scan call sites ===")
for va in (0x103E8D, 0x103E9C):
    fo = va2file(va)
    print(f"VA {va:#x} -> file {fo and hex(fo)}")
    if fo:
        code = elf[fo - 0x18:fo + 0x18]
        for ins in md32.disasm(code, va - 0x18):
            mark = " <<<<" if va <= ins.address < va + 6 else ""
            print(f"  {ins.address:#010x}  {ins.bytes.hex():<16} {ins.mnemonic} {ins.op_str}{mark}")

# ---- locate rsdp_scan function itself (sanity: find 'RSD ' cmp constant) ----
for pat, name in ((struct.pack("<I", 0x20445352), "'RSD ' cmp"),):
    i = elf.find(pat)
    print(f"pattern {name} in file @ {i and hex(i)}")
