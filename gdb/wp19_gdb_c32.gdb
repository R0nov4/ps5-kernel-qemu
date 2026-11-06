target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9e4042c2
c
c
echo \n=== after fixes at second fault ===\n
python
import gdb, struct
inf = gdb.selected_inferior()
def rq(a):
    return struct.unpack("<Q", inf.read_memory(a, 8).tobytes())[0]
rdi = int(gdb.parse_and_eval("$rdi")) & 0xFFFFFFFFFFFFFFFF
print(f"CR2 = 0x{rq(rdi+0x80):x}")
DMAP = 0xffff8e7700000000
cr3 = int(gdb.parse_and_eval("$cr3")) & 0xFFFFFFFFFFFFFFFF
va = 0xffff8e773f2d20bc
pml4e = rq(DMAP + (cr3 & 0x000ffffffffff000) + ((va >> 39) & 0x1FF) * 8)
pdpte = rq(DMAP + (pml4e & 0x000ffffffffff000) + ((va >> 30) & 0x1FF) * 8)
pde = rq(DMAP + (pdpte & 0x000ffffffffff000) + ((va >> 21) & 0x1FF) * 8)
print(f"walk: PML4E=0x{pml4e:x} PDPTE=0x{pdpte:x} PDE=0x{pde:x}")
for test_va in (0xffff8e773f2d20bc, 0xffff8e773ead20bc, 0xffff8e773ea00000):
    try:
        v = rq(test_va)
        print(f"read 0x{test_va:x} OK: 0x{v:x}")
    except Exception as e:
        print(f"read 0x{test_va:x} FAIL: {e}")
end
detach
quit
