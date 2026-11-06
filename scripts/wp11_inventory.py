#!/usr/bin/env python3
"""WP11 Phase A — forensic inventory.
Compare candidate base images for WP7 markers (P1..P11) and WP9/WP10 residue.
Inspect trampoline.elf: ELF phdrs, rsdp_scan call sites (VA 0x103E8D/0x103E9C),
and locate the compiled patch-table entry for the 0xa1926628 gate.
"""
import struct
import capstone

KTEXT = 0x9E3F0000
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

IMGS = {
    "wp6 (15:08)": "./wp3_boot/kernel_raw_wp6.bin",
    "kit WP7 (21:06)": "./kit_build/wp3_boot/kernel_raw.bin",
}

MARKERS = [
    ("P5  ICC-recovery stub 0x9ee30ca0", 0x9EE30CA0),
    ("P7  ICC-submit stub   0x9ee2ff80", 0x9EE2FF80),
    ("P10 cave code        0x9ee2ff90", 0x9EE2FF90),
    ("msgbufp global       0xa1fb8a60", 0xA1FB8A60),
    ("msgbuf_init hook     0x9f025030", 0x9F025030),
    ("W7  PT_RETURN site   0x9ece2400", 0x9ECE2400),
    ("W9  ATTR_WALK site   0x9ecdbc60", 0x9ECDBC60),
    ("W5  dump-copy site   0x9f079d00", 0x9F079D00),
    ("W1  alloc hook site  0x9ea05730", 0x9EA05730),
    ("W8  sysinit2 site    0x9e96b140", 0x9E96B140),
    ("MADT qword [0xa19d3b80]", 0xA19D3B80),
    ("MADT qword [0xa19d3bd0]", 0xA19D3BD0),
    ("MADT next  [0xa0fe32d8]", 0xA0FE32D8),
    ("RSDP global [0xa1d93840]", 0xA1D93840),
    ("PREINIT_POOL[0xa1f37e50]", 0xA1F37E50),
    ("bootverbose [0xa1978858]", 0xA1978858),
    ("bitmap ptr  [0xa1cf3f10]", 0xA1CF3F10),
    ("list-tail   [0xa093e6a0]", 0xA093E6A0),
    ("W3  halt site        0x9ebdf482", 0x9EBDF482),
    ("W3  halt site        0x9ebe0ddd", 0x9EBE0DDD),
]

for name, path in IMGS.items():
    img = open(path, "rb").read()
    print(f"\n===== {name} — {len(img)} bytes =====")
    for label, va in MARKERS:
        off = va - KTEXT
        b = img[off:off+8]
        q = struct.unpack("<Q", b)[0]
        print(f"  {label:30s} bytes={b.hex():<20} q0={q:#018x}")

# ---------------------------------------------------------------- trampoline
print("\n===== trampoline.elf =====")
elf = open("./kit_build/wp3_boot/trampoline.elf", "rb").read()
e_phoff, = struct.unpack_from("<Q", elf, 0x20)
e_phentsize, e_phnum = struct.unpack_from("<HH", elf, 0x36)
print(f"  phoff={e_phoff:#x} phentsize={e_phentsize} phnum={e_phnum}")
segs = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
        struct.unpack_from("<IIQQQQQQ", elf, o)
    if p_type == 1:
        segs.append((p_offset, p_vaddr, p_paddr, p_filesz, p_memsz))
        print(f"  LOAD off={p_offset:#x} vaddr={p_vaddr:#x} paddr={p_paddr:#x} filesz={p_filesz:#x} memsz={p_memsz:#x}")

def va2file(va):
    for off, vaddr, paddr, fsz, msz in segs:
        if vaddr <= va < vaddr + fsz:
            return off + (va - vaddr)
    # fall back: paddr match
    for off, vaddr, paddr, fsz, msz in segs:
        if paddr <= va < paddr + fsz:
            return off + (va - paddr)
    return None

for va in (0x103E8D, 0x103E9C):
    fo = va2file(va)
    print(f"\n  --- VA {va:#x} -> file off {fo and hex(fo)} ---")
    if fo:
        code = elf[fo - 0x20:fo + 0x20]
        for ins in md.disasm(code, va - 0x20):
            mark = " <<<<" if va <= ins.address < va + 8 else ""
            print(f"    {ins.address:#010x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}{mark}")

# patch table: search for qword 0xa1926628 in the elf
needle = struct.pack("<Q", 0xA1926628)
pos = 0
hits = []
while True:
    i = elf.find(needle, pos)
    if i < 0:
        break
    hits.append(i)
    pos = i + 1
print(f"\n  patch-table refs to 0xa1926628: {[hex(h) for h in hits]}")
for h in hits:
    ctx = elf[h - 16:h + 32]
    print(f"    @{h:#x}: prev={elf[h-16:h].hex()} value_q={elf[h+8:h+16].hex()}")
