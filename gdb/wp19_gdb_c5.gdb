target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
python
import gdb
class CrashCatch(gdb.Breakpoint):
    def __init__(self):
        super().__init__("*0xffffffff9e70435b", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.hits = 0
    def stop(self):
        rax = int(gdb.parse_and_eval("$rax")) & 0xFFFFFFFFFFFFFFFF
        self.hits += 1
        ok = (rax >> 48) == 0xFFFF or (rax >> 48) == 0
        if ok and rax != 0:
            return False   # benign hit — auto continue
        # BAD rax (0 or non-canonical) — the crash moment
        print(f"\n=== CRASH MOMENT: rax = 0x{rax:016x} (hits so far: {self.hits}) ===")
        for r in ("rdi","rsi","rdx","rcx","rbx","r8","r9","r10","r11","r12","r13","r14","r15"):
            print(f"  {r}  = 0x{int(gdb.parse_and_eval('$'+r)) & 0xFFFFFFFFFFFFFFFF:016x}")
        print(f"  rip = 0x{int(gdb.parse_and_eval('$rip')) & 0xFFFFFFFFFFFFFFFF:016x}")
        print(f"  rsp = 0x{int(gdb.parse_and_eval('$rsp')) & 0xFFFFFFFFFFFFFFFF:016x}")
        print(f"  rbp = 0x{int(gdb.parse_and_eval('$rbp')) & 0xFFFFFFFFFFFFFFFF:016x}")
        return True
CrashCatch()
end
c
python
import gdb, struct
inf = gdb.selected_inferior()
M = 0xFFFFFFFFFFFFFFFF
rbp = int(gdb.parse_and_eval("$rbp")) & M
print("\n=== RBP CHAIN ===")
f = rbp
for i in range(14):
    try:
        saved_rbp, ret = struct.unpack("<QQ", inf.read_memory(f, 16).tobytes())
        print(f"frame {i}: rbp=0x{f:016x} ret=0x{ret:016x}")
        if saved_rbp == 0 or saved_rbp < 0x1000: break
        f = saved_rbp
    except Exception as e:
        print(f"frame {i}: read err {e}"); break
print("\n=== bump-window cursor [DMAP(0x3F1A0830)] ===")
cur = struct.unpack("<Q", inf.read_memory(0xFFFF8E773F1A0830, 8).tobytes())[0]
print(f"cursor = 0x{cur:016x}  (phys 0x{cur-0xFFFF8E7400000000:x})" if cur > 0xFFFF800000000000 else f"cursor = 0x{cur:016x}")
end
detach
quit
