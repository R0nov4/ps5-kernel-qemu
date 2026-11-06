set pagination off
set confirm off
target remote :1234
break *0x0
continue

python
import gdb
inf = gdb.selected_inferior()
DMAP = 0xFFFF8E7700000000

def rd(addr, n):
    return bytes(inf.read_memory(addr, n))

def rq(addr):
    return int.from_bytes(rd(addr, 8), "little")

def walk(va, pml4_phys):
    pml4 = DMAP + pml4_phys
    pml4e = rq(pml4 + ((va >> 39) & 0x1FF) * 8)
    if not (pml4e & 1):
        return None
    pdpt = DMAP + (pml4e & 0x000FFFFFFFFFF000)
    pdpte = rq(pdpt + ((va >> 30) & 0x1FF) * 8)
    if not (pdpte & 1):
        return None
    if pdpte & 0x80:  # 1GB page
        return (pdpte & 0x000FFFFFC0000000) + (va & 0x3FFFFFFF), "1GB"
    pd = DMAP + (pdpte & 0x000FFFFFFFFFF000)
    pde = rq(pd + ((va >> 21) & 0x1FF) * 8)
    if not (pde & 1):
        return None
    if pde & 0x80:  # 2MB page
        return (pde & 0x000FFFFFFFE00000) + (va & 0x1FFFFF), "2MB"
    pt = DMAP + (pde & 0x000FFFFFFFFFF000)
    pte = rq(pt + ((va >> 12) & 0x1FF) * 8)
    if not (pte & 1):
        return None
    return (pte & 0x000FFFFFFFFFF000) + (va & 0xFFF), "4K"

print("===== pool / ghost correlation at NULL-call =====")
pool = rq(0xffffffffa1f37e50)
print(f"PREINIT_POOL [0xa1f37e50] = {pool:#x}")
for pml4_guess in (0x22254000,):
    r = walk(pool, pml4_guess)
    print(f"pool VA {pool:#x} -> phys {r and (hex(r[0]), r[1])} (via PML4 {pml4_guess:#x})")
r2 = walk(0xffffffffa2615000, 0x22254000)
print(f"pool+0x1000 -> {r2 and (hex(r2[0]), r2[1])}")

print("\n--- pool region first 32 qwords")
try:
    data = rd(pool, 32 * 8)
    for i in range(32):
        print(f"  {pool + i*8:#x}: {int.from_bytes(data[i*8:(i+1)*8], 'little'):#018x}")
except gdb.MemoryError:
    print("  UNMAPPED")

print("\n--- ghost 0x3F014028 DMAP view")
try:
    data = rd(DMAP + 0x3F014028 - 0x18, 16 * 8)
    for i in range(16):
        print(f"  {DMAP + 0x3F014028 - 0x18 + i*8:#x}: {int.from_bytes(data[i*8:(i+1)*8], 'little'):#018x}")
except gdb.MemoryError:
    print("  UNMAPPED")

print("\n--- search pool region for the ghost value")
ghost = 0xFFFF8E773F014028
try:
    blob = rd(pool, 0x2000)
    needle = ghost.to_bytes(8, "little")
    idx = 0
    found = []
    while True:
        i = blob.find(needle, idx)
        if i < 0:
            break
        found.append(hex(pool + i))
        idx = i + 1
    print(f"  ghost ptr found in pool at: {found[:10]} ({len(found)} refs in first 8KB)")
except gdb.MemoryError:
    print("  pool UNMAPPED")
end

detach
quit
