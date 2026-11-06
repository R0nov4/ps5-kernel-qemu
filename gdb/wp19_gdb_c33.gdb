target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9e4042be
c
echo \n=== FIX PATH PDE WRITE ===\n
python
import gdb, struct
inf = gdb.selected_inferior()
M = 0xFFFFFFFFFFFFFFFF
rdi = int(gdb.parse_and_eval("$rdi")) & M
def rq(a):
    return struct.unpack("<Q", inf.read_memory(a, 8).tobytes())[0]
print(f"CR2 = 0x{rq(rdi+0x80):x}")
print(f"rdx (the new PDE value) = 0x{int(gdb.parse_and_eval('$rdx')) & M:x}")
print(f"rcx (the PDE slot) = 0x{int(gdb.parse_and_eval('$rcx')) & M:x}")
end
si
si
echo \n=== after the write ===\n
python
import gdb, struct
inf = gdb.selected_inferior()
def rq(a):
    return struct.unpack("<Q", inf.read_memory(a, 8).tobytes())[0]
rcx = int(gdb.parse_and_eval("$rcx")) & 0xFFFFFFFFFFFFFFFF
print(f"PDE now = 0x{rq(rcx):x}")
for test_va in (0xffff8e773f2d20bc, 0xffff8e773f2ca870):
    try:
        v = rq(test_va)
        print(f"read 0x{test_va:x} OK: 0x{v:x}")
    except Exception as e:
        print(f"read 0x{test_va:x} FAIL: {e}")
end
detach
quit
