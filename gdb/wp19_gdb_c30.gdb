target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9e40422d
c
c
echo \n=== AT THE SECOND FAULT FIX-PATH ===\n
info registers r10
python
import gdb, struct
inf = gdb.selected_inferior()
def rq(a):
    return struct.unpack("<Q", inf.read_memory(a, 8).tobytes())[0]
print(f"r10 (fault VA) = 0x{int(gdb.parse_and_eval('$r10')) & 0xFFFFFFFFFFFFFFFF:x}")
try:
    v = rq(0xffff8e773f2d20bc)
    print(f"DIRECT READ of 0xffff8e773f2d20bc OK: 0x{v:x}")
except Exception as e:
    print(f"DIRECT READ FAILED: {e}")
print(f"PDE[505] = 0x{rq(0xffff8e77222d9fa8):x}")
print(f"PDE[506] = 0x{rq(0xffff8e77222d9fb0):x}")
print(f"PDE[507] = 0x{rq(0xffff8e77222d9fb8):x}")
end
detach
quit
