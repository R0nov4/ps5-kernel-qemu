target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9f0a2338
c
python
import gdb, struct
inf = gdb.selected_inferior()
M = 0xFFFFFFFFFFFFFFFF
r15 = int(gdb.parse_and_eval("$r15")) & M
rbx = int(gdb.parse_and_eval("$rbx")) & M
print(f"\n=== FORK1 SIGACTS STAGE: parent(r15)=0x{r15:x} child(rbx)=0x{rbx:x} ===")
def rq(a):
    try: return struct.unpack("<Q", inf.read_memory(a, 8).tobytes())[0]
    except: return 0
def rd(a, n):
    try: return inf.read_memory(a, n).tobytes()
    except: return b""
print(f"[parent+0x58] = 0x{rq(r15+0x58):x}")
print(f"[child+0x58]  = 0x{rq(rbx+0x58):x}")
print(f"[parent+0x9c] = 0x{rq(r15+0x9c):x}   [child+0x9c] = 0x{rq(rbx+0x9c):x}")
MASK_G, BASE_G = 0xffffffffa1d71df0, 0xffffffffa1d71df8
mask = rq(MASK_G); base = rq(BASE_G)
print(f"mask global [0xa1d71df0] = 0x{mask:x}")
print(f"base global [0xa1d71df8] = 0x{base:x}")
if base > 0xffff000000000000:
    print("table dump [base, base+0x60):")
    d = rd(base, 0x60)
    for i in range(0, 0x60, 8):
        v = struct.unpack("<Q", d[i:i+8])[0] if len(d[i:i+8])==8 else 0
        print(f"  [base+0x{i:02x}] = 0x{v:x}")
# what does a REAL [x+0x58] point to? (the first child's value)
v = rq(0xFFFF8E773F2CA870) if True else 0
print(f"\nmemory at 0xffff8e773f2ca870 (the first child's [+0x58] value):")
d = rd(0xFFFF8E773F2CA870, 0x40)
print(" ", d.hex())
# who else: the proc0 sigacts
print(f"\n[0xa1978f50] (proc0+0x58?) = 0x{rq(0xffffffffa1978f50):x}")
d = rd(rq(0xffffffffa1978f50), 0x40)
print("  memory at that value:", d.hex() if d else "<unreadable>")
end
detach
quit
