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
rdi = int(gdb.parse_and_eval("$rdi")) & M
fr = inf.read_memory(rdi, 0x120).tobytes()
vals = struct.unpack("<24Q", fr[:0xc0])
rbp = vals[8]
print(f"--- rbp chain from tf_rbp=0x{rbp:x} ---")
f = rbp
for i in range(16):
    try:
        saved, ret = struct.unpack("<QQ", inf.read_memory(f, 16).tobytes())
        print(f"frame {i}: rbp=0x{f:x} ret=0x{ret:x}")
        if saved == 0 or (saved & 0xFF000000000000) != (f & 0xFF000000000000): break
        f = saved & M
    except Exception as e:
        print(f"frame {i}: err {e}"); break
end
detach
quit
