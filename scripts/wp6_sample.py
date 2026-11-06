#!/usr/bin/env python3
"""wp6_sample.py — drive QEMU human monitor over unix socket.
Periodic: stop -> RIP + sysinit cursor -> cont.
Final: stop -> full regs + disasm at RIP + sysinit array stats.
Usage: python3 wp6_sample.py [total_sec=90] [step_sec=15]
"""
import socket, sys, time, re

SOCK = "/tmp/wp6mon.sock"
T_TOTAL = float(sys.argv[1]) if len(sys.argv) > 1 else 90.0
T_STEP  = float(sys.argv[2]) if len(sys.argv) > 2 else 15.0

CURSOR_PHYS = 0x219781B0   # [0xffffffffa19781b0] sysinit cursor
END_PHYS    = 0x219781A8   # [0xffffffffa19781a8] filtered end
ARRAY_PHYS  = 0x1FE51FB0   # sysinit_set array (1691 slots x 8B)
VA_TO_PHYS  = lambda va: (va & 0xFFFFFFFF) - 0x80000000  # D-seg identity

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(SOCK)
s.settimeout(4)

def recv_until_prompt():
    buf = b""
    while b"(qemu)" not in buf[-20:]:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        buf += d
    return buf.decode(errors="replace")

def cmd(c):
    s.sendall((c + "\n").encode())
    return recv_until_prompt()

recv_until_prompt()  # banner

def get_rip(out):
    m = re.search(r"RIP=([0-9a-fA-F]+)", out)
    return int(m.group(1), 16) if m else None

def read_qword(phys):
    out = cmd(f"xp /1gx 0x{phys:x}")
    m = re.search(r"0x([0-9a-f]{16})", out)
    return int(m.group(1), 16) if m else None

def reg_of(out, name):
    m = re.search(r"\b" + name + r"=([0-9a-fA-F]+)", out)
    return int(m.group(1), 16) if m else None

t0 = time.time()
next_t = t0 + T_STEP
n_samples = 0
print(f"# sampling every {T_STEP:.0f}s for {T_TOTAL:.0f}s total")
while time.time() - t0 < T_TOTAL - 0.5:
    out = cmd("stop")
    regs = cmd("info registers")
    rip = get_rip(regs)
    r10 = reg_of(regs, "R10"); r14 = reg_of(regs, "R14")
    r12 = reg_of(regs, "R12"); rbx = reg_of(regs, "RBX")
    rsi = reg_of(regs, "RSI")
    sfrag = ""
    if r14 and 0xa05e0000 <= (r14 & 0xffffffff) < 0xa0600000:
        sbytes = cmd(f"x /24bx 0x{r14:x}")
        bs = [int(m, 16) for m in re.findall(r"0x([0-9a-f]{2})\b", sbytes)]
        sfrag = "".join(chr(b) if 32 <= b < 127 else "." for b in bs)
    cur = read_qword(CURSOR_PHYS)
    end = read_qword(END_PHYS)
    n_samples += 1
    el = time.time() - t0
    line = f"[{el:6.1f}s] RIP={rip:012x}" if rip else f"[{el:6.1f}s] RIP=?"
    line += f" r10={r10:x} r14={r14:x} r12={r12:x} rbx={rbx:x} rsi={rsi:x}"
    print(line)
    if sfrag:
        print(f"         str@r14: {sfrag}")
    print(f"         cursor=0x{cur:016x} end=0x{end:016x}")
    cmd("cont")
    remain = next_t - time.time()
    if remain > 0:
        time.sleep(remain)
    next_t += T_STEP

# ---- final frozen dump ----
cmd("stop")
print("\n==== FINAL DUMP ====")
regs = cmd("info registers")
print(regs[:1600])
rip = get_rip(regs)
if rip:
    print(f"==== disasm @ RIP 0x{rip:x} ====")
    print(cmd(f"x /24i 0x{rip:x}"))
# stack qwords (virtual via monitor x, using current cpu context)
rsp_m = re.search(r"RSP=([0-9a-fA-F]+)", regs)
rbp_m = re.search(r"RBP=([0-9a-fA-F]+)", regs)
if rsp_m:
    rsp = int(rsp_m.group(1), 16)
    print(f"==== stack @ RSP 0x{rsp:x} (to RBP+0x40) ====")
    n = 96
    print(cmd(f"x /{n}gx 0x{rsp:x}"))
if rbp_m:
    rbp = int(rbp_m.group(1), 16)
    print(f"==== frame chain from RBP 0x{rbp:x} ====")
    print(cmd(f"x /6gx 0x{rbp:x}"))
    # walk 3 frames: [rbp]=saved rbp, [rbp+8]=ret
    f = rbp
    for lvl in range(4):
        out = cmd(f"x /2gx 0x{f:x}")
        qs = re.findall(r"0x([0-9a-f]{16})", out)
        if len(qs) >= 2:
            saved, ret = int(qs[0], 16), int(qs[1], 16)
            print(f"frame{lvl}: rbp=0x{f:x} saved=0x{saved:x} ret=0x{ret:x}")
            if 0xffffffff9e3f0000 <= ret < 0xffffffffa2224000:
                print(f"  --- caller code at ret-0x20 ---")
                print(cmd(f"x /12i 0x{ret-0x20:x}"))
            if saved == 0 or saved <= f or saved > f + 0x2000:
                break
            f = saved
        else:
            break
# sysinit array stats
cur = read_qword(CURSOR_PHYS)
end = read_qword(END_PHYS)
print(f"cursor=0x{cur:x} end=0x{end:x}")
if end and end > ARRAY_PHYS:
    n_slots = (end - ARRAY_PHYS) // 8
    print(f"filtered slots: {n_slots}")
    # read first 64 slot ptrs, deref sub
    out = cmd(f"xp /64gx 0x{ARRAY_PHYS:x}")
    qs = [int(m, 16) for m in re.findall(r"0x([0-9a-f]{16})", out)]
    qs = [q for q in qs if q]
    done = pend = 0
    for q in qs[:40]:
        sub = read_qword(VA_TO_PHYS(q)) & 0xFFFFFFFF
        if sub == 1:
            done += 1
        elif sub >= 2:
            pend += 1
    print(f"first40 slots: done(stamped)={done} pending(sub>=2)={pend}")
cmd("quit")
