import sys
sys.path.insert(0, "./scripts")
from wp1_lib import disasm, read_u64, read_u32, cstr, rip_target, in_data

def dump(va, name, nbytes=0x200, stop_ret=True):
    print(f"\n===== {name} @ 0x{va:x} =====")
    for ins in disasm(va, nbytes, 300):
        t = rip_target(ins); a = ""
        if t is not None:
            s = cstr(t)
            extra = ""
            if in_data(t):
                v = read_u64(t)
                if v: extra = f" live=0x{v:x}"
            a = f" ; -> 0x{t:x}" + (f" '{s}'" if s else "") + extra
        print(f"0x{ins.address:x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}{a}")
        if stop_ret and ins.mnemonic == "ret": break

dump(0xffffffff9efd3f10, "param_reader (loops in pmap_bootstrap)")
dump(0xffffffff9e6490b0, "gateA_memcpy_helper")
dump(0xffffffff9eebc820, "gateB_inner_check")
# read the static config table + live values used by maxmem getter
print("\nmaxmem table entry: [0x9f280d38] =", hex(read_u64(0xffffffff9f280d38) or 0))
print("[0xa1fa5400] =", hex(read_u64(0xffffffffa1fa5400) or 0))
print("[0xa1fa5408] =", hex(read_u64(0xffffffffa1fa5408) or 0))
print("[0xa1fa5410] =", hex(read_u64(0xffffffffa1fa5410) or 0))
print("[0x9fe4c064] byte chain:", (read_u64(0xffffffff9fe4c060) or 0).to_bytes(8,'little').hex(), "| [0x9fe4c088]=", hex(read_u64(0xffffffff9fe4c088) or 0))
print("[0xa1f37e4c] (recursive slot) =", hex(read_u32(0xffffffffa1f37e4c) or 0))
print("[0xa1f39294] d39 =", hex(read_u32(0xffffffffa1f39294) or 0), " [0xa1f39298] d30 =", hex(read_u32(0xffffffffa1f39298) or 0))
print("[0xa1f37ed0] PT base =", hex(read_u64(0xffffffffa1f37ed0) or 0))
print("[0xa1f37ee0] PT npages =", hex(read_u32(0xffffffffa1f37ee0) or 0))
print("[0xa1f37e60] CR3 =", hex(read_u64(0xffffffffa1f37e60) or 0))
print("[0xa1f37eb8] DMAP(PTend) =", hex(read_u64(0xffffffffa1f37eb8) or 0))
print("[0xa1f37e40] =", hex(read_u64(0xffffffffa1f37e40) or 0))
print("[0xa1f37e50] =", hex(read_u64(0xffffffffa1f37e50) or 0))
print("[0xa1f38308] =", hex(read_u64(0xffffffffa1f38308) or 0))
print("[0xa1f38fe8] =", hex(read_u64(0xffffffffa1f38fe8) or 0))
print("[0xa1f38fe0] (zeroed later) =", hex(read_u64(0xffffffffa1f38fe0) or 0))
print("[0xa1f37e38] =", hex(read_u64(0xffffffffa1f37e38) or 0))
# verify DMAP formula with live values
d39 = read_u32(0xffffffffa1f39294); d30 = read_u32(0xffffffffa1f39298)
base = 0xffff800000000000 | (d39 << 39) | (d30 << 30)
print(f"\nDMAP_BASE from live params = 0x{base:x}")
ptend = read_u64(0xffffffffa1f37eb8)
print(f"DMAP_BASE + PT_base(0x22230000) = 0x{base + 0x22230000:x}  vs live [0xa1f37eb8]=0x{ptend:x}")
print(f"DMAP(PTend_phys=0x24261000) = 0x{base + 0x24261000:x}")
