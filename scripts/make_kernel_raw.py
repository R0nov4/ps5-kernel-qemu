#!/usr/bin/env python3
"""make_kernel_raw.py — rebuild wp3_boot/kernel_raw.bin from
ps5_kernel_1360_reconstructed.elf (no patches applied here; the trampoline
applies patches.inc in-memory at boot time).

The raw image is the flat physical layout of the two PT_LOAD segments:
  phys [0x1E3F0000, 0x22224000)  =  0x3E34000 bytes (62.2 MiB)
    .text: paddr 0x1E3F0000, size 0xCC0000   (offset 0x0000000)
    .data: paddr 0x1F0B0000, size 0x3174000  (offset 0xCC0000)

Usage:
  python3 make_kernel_raw.py [path/to/ps5_kernel_1360_reconstructed.elf] \
                             [path/to/output/kernel_raw.bin]
Defaults search the kit dir, the parent dir and wp3_boot/.
"""
import os, sys, struct

HERE = os.path.dirname(os.path.abspath(__file__))
ELF_NAME = "ps5_kernel_1360_reconstructed.elf"
EXPECT_SIZE = 0x3E34000
TEXT_PADDR, TEXT_FILESZ = 0x1E3F0000, 0xCC0000
DATA_PADDR, DATA_FILESZ = 0x1F0B0000, 0x3174000

def find_elf():
    cands = []
    if len(sys.argv) > 1:
        cands.append(sys.argv[1])
    cands += [
        os.path.join(HERE, ELF_NAME),
        os.path.join(HERE, "..", ELF_NAME),
        os.path.join(HERE, "download", ELF_NAME),
        os.path.join(HERE, "..", "download", ELF_NAME),
        os.path.join(HERE, "wp3_boot", ELF_NAME),
    ]
    for c in cands:
        if c and os.path.isfile(c):
            return os.path.abspath(c)
    sys.exit("ERROR: cannot find %s — pass its path as the first argument" % ELF_NAME)

def out_path():
    if len(sys.argv) > 2:
        return sys.argv[2]
    return os.path.join(HERE, "wp3_boot", "kernel_raw.bin")

def main():
    elf = find_elf()
    out = out_path()
    blob = open(elf, "rb").read()
    if blob[:4] != b"\x7fELF" or blob[4] != 2:
        sys.exit("ERROR: not an ELF64 file: %s" % elf)

    # ---- parse program headers (phdr-driven, then sanity-check) ----
    e_phoff   = struct.unpack_from("<Q", blob, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", blob, 0x36)[0]
    e_phnum   = struct.unpack_from("<H", blob, 0x38)[0]
    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", blob, off)
        p_offset, p_vaddr, p_paddr, p_filesz = struct.unpack_from("<QQQQ", blob, off + 8)
        if p_type == 1:  # PT_LOAD
            loads.append((p_offset, p_paddr, p_filesz, p_flags))
    loads.sort(key=lambda x: x[1])
    if len(loads) < 2:
        sys.exit("ERROR: expected >=2 PT_LOAD segments, found %d" % len(loads))

    base = loads[0][1]
    end = max(paddr + filesz for _, paddr, filesz, _ in loads)
    raw = bytearray(end - base)
    for p_offset, p_paddr, p_filesz, _ in loads:
        raw[p_paddr - base:p_paddr - base + p_filesz] = blob[p_offset:p_offset + p_filesz]

    # ---- sanity checks against the WP2 contract ----
    ok_text = any(p == TEXT_PADDR and f == TEXT_FILESZ for _, p, f, _ in loads)
    ok_data = any(p == DATA_PADDR and f == DATA_FILESZ for _, p, f, _ in loads)
    print("PT_LOAD segments (paddr / filesz):")
    for _, p, f, fl in loads:
        print("  paddr 0x%016x  filesz 0x%09x  flags %d" % (p, f, fl))
    if not (ok_text and ok_data):
        print("WARNING: segment layout differs from the expected WP2 contract "
              "(text 0x%x/0x%x, data 0x%x/0x%x)" % (TEXT_PADDR, TEXT_FILESZ, DATA_PADDR, DATA_FILESZ))
    if len(raw) != EXPECT_SIZE:
        print("WARNING: raw size 0x%x != expected 0x%x (trampoline enforces KERN_SIZE!)"
              % (len(raw), EXPECT_SIZE))

    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "wb") as f:
        f.write(bytes(raw))
    print("wrote %s  (%d bytes, 0x%x)" % (out, len(raw), len(raw)))
    print("NOTE: patches are NOT applied here — the trampoline applies "
          "wp3_boot/patches.inc (see PATCH_COUNT in patches.inc) in memory at boot.")

if __name__ == "__main__":
    main()
