target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9ebe0043
c
echo \n=== AT THE 119x FAULT SITE ===\n
info registers rdi rsi rbx rax r14
python
import gdb, struct
inf = gdb.selected_inferior()
def rq(a):
    return struct.unpack("<Q", inf.read_memory(a, 8).tobytes())[0]
DMAP = 0xffff8e7700000000
cr3 = int(gdb.parse_and_eval("$cr3")) & 0xFFFFFFFFFFFFFFFF
va = 0xffff8e773f2d20bc
pml4e = rq(DMAP + (cr3 & 0x000ffffffffff000) + ((va >> 39) & 0x1FF) * 8)
pdpte = rq(DMAP + (pml4e & 0x000ffffffffff000) + ((va >> 30) & 0x1FF) * 8)
pde = rq(DMAP + (pdpte & 0x000ffffffffff000) + ((va >> 21) & 0x1FF) * 8)
print(f"CR3=0x{cr3:x} PML4E=0x{pml4e:x} PDPTE=0x{pdpte:x} PDE=0x{pde:x}")
if pde & 1 and not (pde & 0x80):
    pte = rq(DMAP + (pde & 0x000ffffffffff000) + ((va >> 12) & 0x1FF) * 8)
    print(f"PTE=0x{pte:x}")
end
detach
quit
