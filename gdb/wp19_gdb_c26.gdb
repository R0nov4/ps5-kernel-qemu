target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9e404000
b *0xffffffff9e403ec5
b *0xffffffff9e7de0e0
c
echo \n=== STOP 1 ===\n
info registers rip
c
echo \n=== STOP 2 ===\n
info registers rip
python
import gdb, struct
inf = gdb.selected_inferior()
try:
    v = struct.unpack("<Q", inf.read_memory(0xffff8e77222d9fa8, 8).tobytes())[0]
    print(f"PDE[505] now = 0x{v:x}")
except Exception as e:
    print("PDE read err", e)
end
c
echo \n=== STOP 3 ===\n
info registers rip
python
import gdb, struct
inf = gdb.selected_inferior()
try:
    v = struct.unpack("<Q", inf.read_memory(0xffff8e77222d9fa8, 8).tobytes())[0]
    print(f"PDE[505] now = 0x{v:x}")
except Exception as e:
    print("PDE read err", e)
end
detach
quit
