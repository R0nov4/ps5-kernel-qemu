target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9f0a17bc
c
python
import gdb, struct
inf = gdb.selected_inferior()
M = 0xFFFFFFFFFFFFFFFF
r15 = int(gdb.parse_and_eval("$r15")) & M
rax = int(gdb.parse_and_eval("$rax")) & M
print(f"\n=== CHILD PROC CREATED: r15=0x{r15:x} rax=0x{rax:x} ===")
ch = rax
v = struct.unpack("<Q", inf.read_memory(ch+0x58, 8).tobytes())[0]
print(f"[child+0x58] = 0x{v:x}")
gdb.execute(f"watch *(unsigned long *)0x{ch+0x58:x}")
# also break at the sigacts read
gdb.execute("b *0xffffffff9f0a2338")
end
c
python
import gdb, struct
inf = gdb.selected_inferior()
M = 0xFFFFFFFFFFFFFFFF
rip = int(gdb.parse_and_eval("$rip")) & M
r15 = int(gdb.parse_and_eval("$r15")) & M
rbx = int(gdb.parse_and_eval("$rbx")) & M
print(f"\n=== STOP rip=0x{rip:x} r15=0x{r15:x} rbx=0x{rbx:x} ===")
if r15 > 0xffff000000000000:
    print(f"[r15+0x58] = 0x{struct.unpack('<Q', inf.read_memory(r15+0x58, 8).tobytes())[0]:x}")
if rbx > 0xffff000000000000:
    print(f"[rbx+0x58] = 0x{struct.unpack('<Q', inf.read_memory(rbx+0x58, 8).tobytes())[0]:x}")
rbp = int(gdb.parse_and_eval("$rbp")) & M
f = rbp
for i in range(8):
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
