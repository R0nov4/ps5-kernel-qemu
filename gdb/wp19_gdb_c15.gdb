target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
watch *(unsigned long *)0xffffffffa1f37eb0
c
python
import gdb, struct
inf = gdb.selected_inferior()
M = 0xFFFFFFFFFFFFFFFF
print(f"\n=== WATCHPOINT HIT ===")
print(f"  rip = 0x{int(gdb.parse_and_eval('$rip')) & M:x}")
v = struct.unpack("<Q", inf.read_memory(0xffffffffa1f37eb0, 8).tobytes())[0]
print(f"  new value = 0x{v:x}")
rbp = int(gdb.parse_and_eval("$rbp")) & M
f = rbp
for i in range(14):
    try:
        saved, ret = struct.unpack("<QQ", inf.read_memory(f, 16).tobytes())
        print(f"frame {i}: rbp=0x{f:x} ret=0x{ret:x}")
        if saved == 0 or (saved & 0xFF000000000000) != (f & 0xFF000000000000): break
        f = saved & M
    except Exception as e:
        break
end
x/6i $rip
detach
quit
