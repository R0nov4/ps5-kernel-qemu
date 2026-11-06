target remote :1234
set pagination off
set confirm off
echo \n=== WP19 PHASE-1: WHERE IS THE KERNEL AFTER gc_suspend_resume? ===\n
echo \n=== REGISTERS ===\n
info registers
echo \n=== RIP CONTEXT ===\n
x/12i $rip
echo \n=== RBP CHAIN (manual walk) ===\n
python
import gdb
inf = gdb.selected_inferior()
rbp = int(gdb.parse_and_eval("$rbp"))
rsp = int(gdb.parse_and_eval("$rsp"))
rip = int(gdb.parse_and_eval("$rip"))
print(f"RIP=0x{rip:016x}  RBP=0x{rbp:016x}  RSP=0x{rsp:016x}")
MI_LO, MI_HI = 0xffffffff9e9261f0, 0xffffffff9e9263d0
print(f"RIP inside mi_startup? {MI_LO <= rip < MI_HI}")
f = rbp
for i in range(16):
    try:
        frame = inf.read_memory(f, 16).tobytes()
        import struct
        saved_rbp, ret = struct.unpack("<QQ", frame)
        if saved_rbp == 0 or saved_rbp < 0x1000 or (saved_rbp >> 40) != (f >> 40):
            print(f"frame {i}: rbp=0x{f:016x} ret=0x{ret:016x}  <chain end>")
            break
        print(f"frame {i}: rbp=0x{f:016x} ret=0x{ret:016x}")
        f = saved_rbp
    except Exception as e:
        print(f"frame {i}: read error at 0x{f:x}: {e}")
        break
end
echo \n=== SYSINIT FRONTIER SCAN (in-memory done-stamps) ===\n
python
import gdb, struct
inf = gdb.selected_inferior()
START = 0xffffffff9fe51fb0
END_G = 0xffffffffa19781a8      # compacted end global
CUR_G = 0xffffffffa19781b0      # scan base global
RUN_G = 0xffffffffa1978198      # being_run global
def g(a):
    return struct.unpack("<Q", inf.read_memory(a, 8).tobytes())[0]
end_v, cur_v, run_v = g(END_G), g(CUR_G), g(RUN_G)
print(f"compact-end [0xa19781a8] = 0x{end_v:x}  (slots={ (end_v-START)//8 })")
print(f"scan-base  [0xa19781b0] = 0x{cur_v:x}")
print(f"being-run  [0xa1978198] = 0x{run_v:x}")
n = (end_v - START) // 8
slots = struct.unpack(f"<{n}Q", inf.read_memory(START, end_v - START).tobytes())
done = 0; dummy = 0; pend = []
for i, p in enumerate(slots):
    if p == 0:
        dummy += 1
        continue
    try:
        sub = struct.unpack("<I", inf.read_memory(p, 4).tobytes())[0]
    except Exception:
        continue
    if sub == 1:
        done += 1
    elif sub == 0:
        dummy += 1
    else:
        pend.append((i, p, sub))
print(f"slots={n} done-stamped={done} dummy/zero={dummy} PENDING(si_sub>=2)={len(pend)}")
print("--- first 16 pending entries ---")
for i, p, sub in pend[:16]:
    try:
        order = struct.unpack("<I", inf.read_memory(p + 4, 4).tobytes())[0]
        thunk = struct.unpack("<Q", inf.read_memory(p + 8, 8).tobytes())[0]
        udata = struct.unpack("<Q", inf.read_memory(p + 0x10, 8).tobytes())[0]
        f18 = struct.unpack("<Q", inf.read_memory(p + 0x18, 8).tobytes())[0]
        u20 = struct.unpack("<Q", inf.read_memory(p + 0x20, 8).tobytes())[0]
        print(f"IDX {i:5d} ptr=0x{p:x} sub=0x{sub:x} ord=0x{order:x} thunk=0x{thunk:x} udata=0x{udata:x} f18=0x{f18:x} u20=0x{u20:x}")
    except Exception as e:
        print(f"IDX {i}: err {e}")
print("--- last 3 done-stamped entries (for order check) ---")
cnt = 0
for i in range(len(slots) - 1, -1, -1):
    p = slots[i]
    if p == 0: continue
    try: sub = struct.unpack("<I", inf.read_memory(p, 4).tobytes())[0]
    except Exception: continue
    if sub == 1:
        order = struct.unpack("<I", inf.read_memory(p + 4, 4).tobytes())[0]
        thunk = struct.unpack("<Q", inf.read_memory(p + 8, 8).tobytes())[0]
        print(f"IDX {i:5d} ptr=0x{p:x} ord=0x{order:x} thunk=0x{thunk:x}")
        cnt += 1
        if cnt >= 3: break
end
echo \n=== STACK DUMP (offline frame analysis) ===\n
dump binary memory /tmp/w19_stack.bin $rsp $rsp+0x400
echo dumped /tmp/w19_stack.bin\n
detach
quit
