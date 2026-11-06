target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9e7de0e0
c
python
import gdb, struct
inf = gdb.selected_inferior()
M = 0xFFFFFFFFFFFFFFFF
DMAP = 0xFFFF8E7700000000
cr3 = int(gdb.parse_and_eval("$cr3")) & M
rdi = int(gdb.parse_and_eval("$rdi")) & M
fr = inf.read_memory(rdi, 0xc0).tobytes()
fault_va = struct.unpack("<Q", fr[0x80:0x88])[0]
print(f"CR3(phys) = 0x{cr3:x}   fault VA = 0x{fault_va:x}")
def rq(a):
    return struct.unpack("<Q", inf.read_memory(a, 8).tobytes())[0]
def walk(va, label):
    pml4 = DMAP + (cr3 & 0x000ffffffffff000)
    pml4e = rq(pml4 + ((va >> 39) & 0x1FF) * 8)
    pdpte = rq(DMAP + (pml4e & 0x000ffffffffff000) + ((va >> 30) & 0x1FF) * 8)
    line = f"{label} 0x{va:x}: PML4E=0x{pml4e:x} PDPTE=0x{pdpte:x}"
    if pdpte & 1 and not (pdpte & 0x80):
        pde = rq(DMAP + (pdpte & 0x000ffffffffff000) + ((va >> 21) & 0x1FF) * 8)
        line += f" PDE=0x{pde:x}"
        if pde & 1 and not (pde & 0x80):
            pte = rq(DMAP + (pde & 0x000ffffffffff000) + ((va >> 12) & 0x1FF) * 8)
            line += f" PTE=0x{pte:x}"
    print(line)
walk(fault_va, "FAULT ")
for good in (0xffff8e773f2ca870, 0xffff8e773f1a1000, 0xffff8e773f200000, 0xffff8e773f2d0000, 0xffff8e77222550a0):
    walk(good, "good  ")
end
detach
quit
