target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9f0a162b
c
python
import gdb, struct
inf = gdb.selected_inferior()
M = 0xFFFFFFFFFFFFFFFF
rax = int(gdb.parse_and_eval("$rax")) & M
print(f"\n=== THREAD ALLOC RETURNED: rax=0x{rax:x} ===")
th = rax
gdb.execute(f"watch *(unsigned long *)0x{th+0x58:x}")
gdb.execute("b *0xffffffff9f0a2338")
end
c
python
import gdb, struct
inf = gdb.selected_inferior()
M = 0xFFFFFFFFFFFFFFFF
rip = int(gdb.parse_and_eval("$rip")) & M
th = 0xFFFF8E773F2D2000
v = struct.unpack("<Q", inf.read_memory(th+0x58, 8).tobytes())[0]
print(f"\n=== STOP rip=0x{rip:x}  [child_thread+0x58] = 0x{v:x} ===")
rbp = int(gdb.parse_and_eval("$rbp")) & M
f = rbp
for i in range(10):
    try:
        saved, ret = struct.unpack("<QQ", inf.read_memory(f, 16).tobytes())
        print(f"frame {i}: rbp=0x{f:x} ret=0x{ret:x}")
        if saved == 0 or (saved & 0xFF000000000000) != (f & 0xFF000000000000): break
        f = saved & M
    except Exception as e:
        break
end
detach
quit
