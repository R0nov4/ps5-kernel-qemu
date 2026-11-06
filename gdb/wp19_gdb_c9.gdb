target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
watch *(unsigned long *)0xffffffffa1978f50
c
python
import gdb, struct
inf = gdb.selected_inferior()
M = 0xFFFFFFFFFFFFFFFF
print(f"\n=== WATCHPOINT HIT ===")
print(f"  rip = 0x{int(gdb.parse_and_eval('$rip')) & M:x}")
print(f"  new value = 0x{struct.unpack('<Q', inf.read_memory(0xffffffffa1978f50, 8).tobytes())[0]:x}")
rbp = int(gdb.parse_and_eval("$rbp")) & M
print(f"--- rbp chain from 0x{rbp:x} ---")
f = rbp
for i in range(14):
    try:
        saved, ret = struct.unpack("<QQ", inf.read_memory(f, 16).tobytes())
        print(f"frame {i}: rbp=0x{f:x} ret=0x{ret:x}")
        if saved == 0 or (saved & 0xFF000000000000) != (f & 0xFF000000000000): break
        f = saved & M
    except Exception as e:
        print(f"frame {i}: err {e}"); break
end
x/8i $rip
detach
quit
