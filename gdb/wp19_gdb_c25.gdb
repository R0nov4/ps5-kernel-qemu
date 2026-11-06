target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9e403ec5
b *0xffffffff9e7de0e0
c
python
import gdb
M = 0xFFFFFFFFFFFFFFFF
rip = int(gdb.parse_and_eval("$rip")) & M
if rip == 0xffffffff9e403ec5:
    print(f"\n=== PDE-WRITE REACHED ===")
    rax = int(gdb.parse_and_eval("$rax")) & M
    print(f"PD VA (rax) = 0x{rax:x}")
    import struct
    inf = gdb.selected_inferior()
    v = struct.unpack("<Q", inf.read_memory(rax + 0xfa8, 8).tobytes())[0]
    print(f"PDE[505] BEFORE = 0x{v:x}")
else:
    print(f"\n=== TRAP FIRST (rip=0x{rip:x}) — the PDE write NEVER RAN! ===")
end
c
python
import gdb, struct
inf = gdb.selected_inferior()
M = 0xFFFFFFFFFFFFFFFF
rip = int(gdb.parse_and_eval("$rip")) & M
print(f"\n=== SECOND STOP rip=0x{rip:x} ===")
if rip == 0xffffffff9e403ec5:
    rax = int(gdb.parse_and_eval("$rax")) & M
    v = struct.unpack("<Q", inf.read_memory(rax + 0xfa8, 8).tobytes())[0]
    print(f"PDE[505] BEFORE = 0x{v:x}")
end
detach
quit
