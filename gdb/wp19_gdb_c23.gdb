target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
python
import gdb
class Count(gdb.Breakpoint):
    def __init__(self, addr, name):
        super().__init__(f"*{addr}", gdb.BP_BREAKPOINT, internal=True)
        self.silent = True
        self.name = name
        self.n = 0
    def stop(self):
        self.n += 1
        if self.n in (1, 2, 3, 5, 10, 20, 50, 100, 200, 500):
            M = 0xFFFFFFFFFFFFFFFF
            rip = int(gdb.parse_and_eval("$rip")) & M
            print(f"[{self.name} #{self.n}] rip=0x{rip:x}")
        if self.n >= 600:
            print(f"[{self.name}] giving up at {self.n}")
            return True
        return False
Count("0xffffffff9e403e00", "pop")
Count("0xffffffff9ecd01a0", "ptfill")
end
c
python
import gdb
print("\n=== FINAL COUNTS (target stopped or crashed) ===")
try:
    print(f"rip = 0x{int(gdb.parse_and_eval('$rip')) & 0xFFFFFFFFFFFFFFFF:x}")
except: pass
end
detach
quit
