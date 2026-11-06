#!/usr/bin/env python3
"""WP2 STEP 3b — THE RECONSTRUCTOR: 13.60 dump -> ps5_kernel_1360_reconstructed.elf

Patches applied to the live dump image:
  1. sysinit_set array rebuilt: [105 dummies sorted by order] + [1235 unique reals
     in dump order] + [351 zero slots]
  2. every unique real sysinit struct: si_sub := synthetic group (2..N) —
     proven ZERO-SWAP under the kernel's own single-sweep sort
  3. mi_startup re-entrancy globals zeroed: 0xa1978198/1a0/1a8/1b0 := 0
  4. 11 held mutexes released: mtx_lock(base+0x18) := 4, recurse(base+0xC) := 0
  5. image CUT at 0xffffffffa2224000 (true ELF image end; runtime heap excluded)

ELF64:
  e_entry = 0xffffffff9e642a90 (btext)
  PT_LOAD #1 .text: vaddr 0xffffffff9e3f0000  paddr 0x1E3F0000  R+X  0xCC0000
  PT_LOAD #2 .data: vaddr 0xffffffff9f0b0000  paddr 0x1F0B0000  R+W  0x3174000
"""
import sys, struct, json
sys.path.insert(0, "./scripts")
import wp1_lib as L

DUMP = "./ps5/dump13/kernel-13.60-live.bin"
OUT_ELF = "./download/ps5_kernel_1360_reconstructed.elf"

TEXT_VA, TEXT_SZ = 0xFFFFFFFF9E3F0000, 0xCC0000
DATA_VA, DATA_SZ = 0xFFFFFFFF9F0B0000, 0x3174000          # image end 0xa2224000
ENTRY = 0xFFFFFFFF9E642A90
SET_LO = 0xFFFFFFFF9FE51FB0

blob = L._blob
text = bytearray(blob[0:TEXT_SZ])
data = bytearray(blob[L.va2off(DATA_VA): L.va2off(DATA_VA) + DATA_SZ])

def dva2off(va):
    return va - DATA_VA

def w32_data(va, val):
    struct.pack_into("<I", data, dva2off(va), val & 0xFFFFFFFF)

def w64_data(va, val):
    struct.pack_into("<Q", data, dva2off(va), val & 0xFFFFFFFFFFFFFFFF)

def r64_data(va):
    return struct.unpack_from("<Q", data, dva2off(va))[0]

# ---------------- reproduce the Step-3 plan (self-contained) ----------------
slots = []
for k in range(1691):
    p = L.read_u64(SET_LO + 8 * k)
    slots.append({"slot": k, "ptr": p, "sub": L.read_u32(p),
                  "order": L.read_u32(p + 4)})
dummies = [s for s in slots if s["sub"] == 0]
reals = [s for s in slots if s["sub"] == 1]
seen, unique_reals, dup_count = set(), [], 0
for s in reals:
    if s["ptr"] in seen:
        dup_count += 1
    else:
        seen.add(s["ptr"])
        unique_reals.append(s)

group, prev_order = 2, None
for s in unique_reals:
    if prev_order is not None and s["order"] < prev_order:
        group += 1
    s["new_sub"] = group
    prev_order = s["order"]
n_groups = group - 1
dummies_sorted = sorted(dummies, key=lambda s: (s["order"], s["ptr"]))
final = dummies_sorted + unique_reals
assert len(final) + dup_count == 1691

# ---------------- PATCH 1+2: array slots + struct si_sub ----------------
for i, s in enumerate(final):
    w64_data(SET_LO + 8 * i, s["ptr"])
for i in range(len(final), 1691):
    w64_data(SET_LO + 8 * i, 0)                       # zero the duplicate slots
for s in unique_reals:
    w32_data(s["ptr"], s["new_sub"])                  # si_sub := synthetic group

# ---------------- PATCH 3: mi_startup globals ----------------
for va in (0xFFFFFFFFA1978198, 0xFFFFFFFFA19781A0, 0xFFFFFFFFA19781A8, 0xFFFFFFFFA19781B0):
    w64_data(va, 0)

# ---------------- PATCH 4: held mutexes -> FREE ----------------
HELD = [0xFFFFFFFF9FE6A568, 0xFFFFFFFF9FE6A598, 0xFFFFFFFF9FEBEF08,
        0xFFFFFFFFA05F89A0, 0xFFFFFFFFA095A370, 0xFFFFFFFFA095A3D0,
        0xFFFFFFFFA095A4F0, 0xFFFFFFFFA095A550, 0xFFFFFFFFA095A5B0,
        0xFFFFFFFFA095C4A0, 0xFFFFFFFFA0FE86C8]
for base in HELD:
    w64_data(base + 0x18, 4)          # mtx_lock := 4 (FREE)
    w32_data(base + 0x0C, 0)          # mtx_recurse := 0

# ---------------- verify patches (read from the PATCHED data!) ----------------
def r32_data(va):
    return struct.unpack_from("<I", data, dva2off(va))[0]

ok = True
n_real = sum(1 for i in range(1691) if (v := r64_data(SET_LO + 8 * i)) and r32_data(v) >= 2)
n_dum = sum(1 for i in range(1691) if (v := r64_data(SET_LO + 8 * i)) and r32_data(v) < 2)
n_zero = sum(1 for i in range(1691) if r64_data(SET_LO + 8 * i) == 0)
print(f"patched array: real(si_sub>=2)={n_real} dummy(si_sub<2)={n_dum} zero-slots={n_zero}")
print(f"groups={n_groups}  expected real=1235 dummy=105 zero=351")
ok = (n_real, n_dum, n_zero) == (1235, 105, 351)
assert ok

# ---------------- BUILD ELF64 ----------------
EHDR_SZ, PHDR_SZ, SHDR_SZ = 64, 56, 64
N_PHDR = 2
N_SHDR = 4                     # NULL, .text, .data, .shstrtab
off_phdr = EHDR_SZ
off_text = 0x1000
off_data = (off_text + TEXT_SZ + 0xFFF) & ~0xFFF
off_shstr = (off_data + DATA_SZ + 0xFFF) & ~0xFFF
off_shdr = (off_shstr + 0x40) & ~0x7

shstrtab = b"\0.text\0.data\0.shstrtab\0"
name_text = 1
name_data = 7
name_shstr = 13

elf = bytearray(off_shdr + N_SHDR * SHDR_SZ)

# --- ELF header ---
ei = bytearray(b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\0" * 7)
struct.pack_into("<16s", elf, 0, bytes(ei))
struct.pack_into("<HHIQQQIHHHHHH", elf, 16,
    2,            # e_type = ET_EXEC
    0x3E,         # e_machine = EM_X86_64
    1,            # e_version
    ENTRY,        # e_entry
    off_phdr,     # e_phoff
    off_shdr,     # e_shoff
    0,            # e_flags
    EHDR_SZ,      # e_ehsize
    PHDR_SZ,      # e_phentsize
    N_PHDR,       # e_phnum
    SHDR_SZ,      # e_shentsize
    N_SHDR,       # e_shnum
    3)            # e_shstrndx -> .shstrtab section index

# --- program headers ---
def phdr(idx, ptype, flags, off, vaddr, paddr, filesz, memsz, align):
    struct.pack_into("<IIQQQQQQ", elf, off_phdr + idx * PHDR_SZ,
                     ptype, flags, off, vaddr, paddr, filesz, memsz, align)

phdr(0, 1, 5,               # PT_LOAD, R+X
     off_text, TEXT_VA, 0x1E3F0000, TEXT_SZ, TEXT_SZ, 0x1000)
phdr(1, 1, 6,               # PT_LOAD, R+W
     off_data, DATA_VA, 0x1F0B0000, DATA_SZ, DATA_SZ, 0x1000)

# --- section headers ---
def shdr(idx, name, stype, flags, addr, off, size, link, info, addralign, entsize):
    struct.pack_into("<IIQQQQIIQQ", elf, off_shdr + idx * SHDR_SZ,
                     name, stype, flags, addr, off, size, link, info, addralign, entsize)

shdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)                     # SHT_NULL
shdr(1, name_text, 1, 0x6, TEXT_VA, off_text, TEXT_SZ, 0, 0, 0x1000, 0)   # .text PROGBITS AX
shdr(2, name_data, 1, 0x3, DATA_VA, off_data, DATA_SZ, 0, 0, 0x1000, 0)   # .data PROGBITS WA
shdr(3, name_shstr, 3, 0, 0, off_shstr, len(shstrtab), 0, 0, 1, 0)        # .shstrtab

# --- contents ---
elf[off_text: off_text + TEXT_SZ] = text
elf[off_data: off_data + DATA_SZ] = data
elf[off_shstr: off_shstr + len(shstrtab)] = shstrtab

with open(OUT_ELF, "wb") as f:
    f.write(elf)

print(f"\nwrote {OUT_ELF}  ({len(elf)} bytes = {len(elf)/2**20:.1f} MiB)")
print(f"  .text: off=0x{off_text:x} vaddr=0x{TEXT_VA:x} paddr=0x1E3F0000 size=0x{TEXT_SZ:x}")
print(f"  .data: off=0x{off_data:x} vaddr=0x{DATA_VA:x} paddr=0x1F0B0000 size=0x{DATA_SZ:x}")
print(f"  e_entry = 0x{ENTRY:x}")
