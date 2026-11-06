target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9e7de0e0
c
echo \n=== TRAP CAUGHT — thread0 sched state ===\n
python
import gdb, struct
inf = gdb.selected_inferior()
M = 0xFFFFFFFFFFFFFFFF
def rq(a, n=8):
    try: return struct.unpack(f"<{n}Q", inf.read_memory(a, 8*n).tobytes())
    except Exception as e: return [f"ERR {e}"]
t0 = 0xFFFFFFFFA1978860   # thread0 (static)
print(f"thread0 @ 0x{t0:x}")
print(f"  [+0x00] (class ptr)     = 0x{rq(t0)[0]:x}")
print(f"  [+0x60] (sched slot A)  = 0x{rq(t0+0x60)[0]:x}")
print(f"  [+0x608](sched slot B)  = 0x{rq(t0+0x608)[0]:x}")
w = struct.unpack("<H", inf.read_memory(t0+0x600, 2).tobytes())[0]
print(f"  [+0x600] flags word     = 0x{w:x}  (bit0={w&1})")
g = 0x9EAA544A + 7 + 0x325F787
print(f"static class global @ 0x{g:x} = 0x{rq(g)[0]:x}")
# also: the new CHILD thread object (rsi at the sched_fork call = tf_rbx)
ch = 0xFFFF8E773F2D1000
print(f"child thread @ 0x{ch:x}")
print(f"  [+0x00] = 0x{rq(ch)[0]:x}   [+0x60] = 0x{rq(ch+0x60)[0]:x}   [+0x600] flags = 0x{struct.unpack('<H', inf.read_memory(ch+0x600, 2).tobytes())[0]:x}")
# scan .data region for a static sched object pattern: search near the class global
print("\n=== globals window @0xA1D04BC0 (around the class ptr) ===")
for i, v in enumerate(rq(0xA1D04BC0, 16)):
    print(f"  [0x{0xA1D04BC0 + i*8:x}] = 0x{v:x}")
end
detach
quit
