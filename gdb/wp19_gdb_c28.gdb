target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9e403ec5
c
echo \n=== PDE WRITE ARMED (after pop write) ===\n
c
echo \n=== next stop ===\n
info registers rip rbx rax r13 r14 r15
x/3i $rip-6
python
import gdb, struct
inf = gdb.selected_inferior()
try:
    v = struct.unpack("<Q", inf.read_memory(0xffff8e77222d9fa8, 8).tobytes())[0]
    print(f"PDE[505] = 0x{v:x}")
except Exception as e:
    print("err", e)
end
detach
quit
