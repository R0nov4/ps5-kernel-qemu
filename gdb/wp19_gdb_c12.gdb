target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9f0a1ef6
b *0xffffffff9f0a2338
c
python
import gdb, struct
inf = gdb.selected_inferior()
M = 0xFFFFFFFFFFFFFFFF
rip = int(gdb.parse_and_eval("$rip")) & M
def rq(a):
    try: return struct.unpack("<Q", inf.read_memory(a, 8).tobytes())[0]
    except: return 0
def rdx_(a):
    try: return struct.unpack("<Q", inf.read_memory(a, 8).tobytes())[0]
    except: return 0
print(f"\n=== HIT rip=0x{rip:x} ===")
if rip == 0xffffffff9f0a1ef6:
    rdi = int(gdb.parse_and_eval("$rdi")) & M
    r12 = int(gdb.parse_and_eval("$r12")) & M
    rbx = int(gdb.parse_and_eval("$rbx")) & M
    print(f"domain-assigner call: rdi=0x{rdi:x} r12=0x{r12:x} rbx=0x{rbx:x}")
    for name, o in [("rdi", rdi), ("r12", r12), ("rbx", rbx)]:
        if o > 0xffff000000000000:
            print(f"  {name}+0x58 = 0x{rq(o+0x58):x}   {name}+0x98 = 0x{rq(o+0x98):x}   {name}+0x9c(dword) = 0x{rq(o+0x9c) & 0xffffffff:x}")
    print(f"  mask[0xa2171df0] = 0x{rq(0xffffffffa2171df0):x}   table[0xa2171df8] = 0x{rq(0xffffffffa2171df8):x}")
    # continue to after the assigner
    gdb.execute("tbreak *0xffffffff9f0a1efb")
    gdb.execute("c")
    rdi2 = int(gdb.parse_and_eval("$rdi")) & M
    print(f"  after assigner: rdi=0x{rdi2:x} [rdi+0x58] = 0x{rq(rdi2+0x58):x}")
end
c
python
import gdb, struct
inf = gdb.selected_inferior()
M = 0xFFFFFFFFFFFFFFFF
rip = int(gdb.parse_and_eval("$rip")) & M
def rq(a):
    try: return struct.unpack("<Q", inf.read_memory(a, 8).tobytes())[0]
    except: return 0
print(f"\n=== SECOND HIT rip=0x{rip:x} ===")
r15 = int(gdb.parse_and_eval("$r15")) & M
rbx = int(gdb.parse_and_eval("$rbx")) & M
r12 = int(gdb.parse_and_eval("$r12")) & M
print(f"r15(parent)=0x{r15:x} rbx=0x{rbx:x} r12=0x{r12:x}")
print(f"[r15+0x58] = 0x{rq(r15+0x58):x}   [rbx+0x58] = 0x{rq(rbx+0x58):x}   [r12+0x58] = 0x{rq(r12+0x58):x}")
print(f"[rbx+0x98] = 0x{rq(rbx+0x98):x}  [r15+0x98] = 0x{rq(r15+0x98):x}")
print(f"mask[0xa2171df0] = 0x{rq(0xffffffffa2171df0):x}   table[0xa2171df8] = 0x{rq(0xffffffffa2171df8):x}")
end
detach
quit
