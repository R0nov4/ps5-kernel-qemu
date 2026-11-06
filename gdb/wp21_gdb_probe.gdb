target remote :1234
set pagination off
set confirm off
echo \n=== WP21 PROBE: THE done COUNTER AT THE FRONTIER STOP ===\n
python
import gdb, struct
inf = gdb.selected_inferior()
rip = int(gdb.parse_and_eval("$rip"))
rsp = int(gdb.parse_and_eval("$rsp"))
print(f"RIP=0x{rip:016x}  RSP=0x{rsp:016x}")
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
print("--- first 6 pending entries (the WP22 march head) ---")
for i, p, sub in pend[:6]:
    try:
        order = struct.unpack("<I", inf.read_memory(p + 4, 4).tobytes())[0]
        thunk = struct.unpack("<Q", inf.read_memory(p + 8, 8).tobytes())[0]
        print(f"IDX {i:5d} ptr=0x{p:x} sub=0x{sub:x} ord=0x{order:x} thunk=0x{thunk:x}")
    except Exception as e:
        print(f"IDX {i}: err {e}")
end
echo \n=== disasm around RIP (expect the G26 park: cli/hlt) ===\n
x/6i $rip
detach
quit
