target remote :1234
set pagination off
set confirm off
echo \n=== WP19 PHASE-2: confirm permanent stall + detail capture ===\n
python
import gdb, struct
inf = gdb.selected_inferior()
rsp = int(gdb.parse_and_eval("$rsp"))
rbp = int(gdb.parse_and_eval("$rbp"))
rip = int(gdb.parse_and_eval("$rip"))
print(f"RIP=0x{rip:016x}  RBP=0x{rbp:016x}  RSP=0x{rsp:016x}")
ret0 = struct.unpack("<Q", inf.read_memory(rsp, 8).tobytes())[0]
print(f"[RSP] (return addr of the current call) = 0x{ret0:x}")
# sysinit stamps
START = 0xffffffff9fe51fb0
end_v = struct.unpack("<Q", inf.read_memory(0xffffffffa19781a8, 8).tobytes())[0]
n = (end_v - START) // 8
slots = struct.unpack(f"<{n}Q", inf.read_memory(START, end_v - START).tobytes())
done = 0; pend = []
for i, p in enumerate(slots):
    if p == 0: continue
    sub = struct.unpack("<I", inf.read_memory(p, 4).tobytes())[0]
    if sub == 1: done += 1
    elif sub >= 2: pend.append((i, p, sub))
print(f"slots={n} done={done} pending={len(pend)}")
if pend:
    i, p, sub = pend[0]
    print(f"FIRST PENDING: IDX {i} ptr=0x{p:x} sub=0x{sub:x}")
# idle thread gs:[8]
# (gs base read via register gsBase not exposed; read pcpu seed image instead later)
end
echo \n=== registers (compact) ===\n
info registers rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 rip
echo \n=== disasm around RIP ===\n
x/6i $rip
detach
quit
