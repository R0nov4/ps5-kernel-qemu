target remote :1234
set pagination off
set confirm off
echo \n=== WP20 PROBE: WHERE IS THE WALKER NOW? ===\n
python
import gdb, struct
inf = gdb.selected_inferior()
rsp = int(gdb.parse_and_eval("$rsp"))
rbp = int(gdb.parse_and_eval("$rbp"))
rip = int(gdb.parse_and_eval("$rip"))
print(f"RIP=0x{rip:016x}  RBP=0x{rbp:016x}  RSP=0x{rsp:016x}")
MI_LO, MI_HI = 0xffffffff9e9261f0, 0xffffffff9e9263d0
print(f"RIP inside mi_startup? {MI_LO <= rip < MI_HI}")
# --- sysinit done-stamp scan ---
START = 0xffffffff9fe51fb0
END_G = 0xffffffffa19781a8      # compacted end global
CUR_G = 0xffffffffa19781b0      # scan base global
RUN_G = 0xffffffffa1978198      # being-run global
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
print("--- first 12 pending entries ---")
for i, p, sub in pend[:12]:
    try:
        order = struct.unpack("<I", inf.read_memory(p + 4, 4).tobytes())[0]
        thunk = struct.unpack("<Q", inf.read_memory(p + 8, 8).tobytes())[0]
        udata = struct.unpack("<Q", inf.read_memory(p + 0x10, 8).tobytes())[0]
        print(f"IDX {i:5d} ptr=0x{p:x} sub=0x{sub:x} ord=0x{order:x} thunk=0x{thunk:x} udata=0x{udata:x}")
    except Exception as e:
        print(f"IDX {i}: err {e}")
# --- the rbp chain (manual walk) ---
print("--- RBP CHAIN ---")
f = rbp
for i in range(14):
    try:
        frame = inf.read_memory(f, 16).tobytes()
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
echo \n=== disasm around RIP ===\n
x/10i $rip
echo \n=== registers ===\n
info registers rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 rip
detach
quit
