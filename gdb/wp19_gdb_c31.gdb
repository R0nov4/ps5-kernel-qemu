target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9e40422d
c
echo \n=== FIRST FAULT FIX PATH ===\n
python
import gdb, struct
inf = gdb.selected_inferior()
def rq(a):
    return struct.unpack("<Q", inf.read_memory(a, 8).tobytes())[0]
rdi = int(gdb.parse_and_eval("$rdi")) & 0xFFFFFFFFFFFFFFFF
print(f"CR2 = 0x{rq(rdi+0x80):x}")
for va in (0xffff8e773f2ca870, 0xffff8e773f2ce068, 0xffff8e773f2d20bc, 0xffff8e773f1a1000):
    try:
        v = rq(va)
        print(f"read 0x{va:x} OK: 0x{v:x}")
    except Exception as e:
        print(f"read 0x{va:x} FAIL: {e}")
end
c
echo \n=== SECOND FAULT FIX PATH ===\n
python
import gdb, struct
inf = gdb.selected_inferior()
def rq(a):
    return struct.unpack("<Q", inf.read_memory(a, 8).tobytes())[0]
rdi = int(gdb.parse_and_eval("$rdi")) & 0xFFFFFFFFFFFFFFFF
print(f"CR2 = 0x{rq(rdi+0x80):x}")
for va in (0xffff8e773f2ca870, 0xffff8e773f2d20bc, 0xffff8e773f1a1000):
    try:
        v = rq(va)
        print(f"read 0x{va:x} OK: 0x{v:x}")
    except Exception as e:
        print(f"read 0x{va:x} FAIL: {e}")
end
detach
quit
