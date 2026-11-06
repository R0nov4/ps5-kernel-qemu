target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
watch *(unsigned long *)0xffffffffa1f37eb0
python
import gdb
class W(gdb.Breakpoint):
    def __init__(self):
        super().__init__("*(unsigned long *)0xffffffffa1f37eb0", gdb.BP_WATCHPOINT, internal=True)
        self.silent = True
        self.n = 0
    def stop(self):
        self.n += 1
        M = 0xFFFFFFFFFFFFFFFF
        rip = int(gdb.parse_and_eval("$rip")) & M
        import struct
        inf = gdb.selected_inferior()
        v = struct.unpack("<Q", inf.read_memory(0xffffffffa1f37eb0, 8).tobytes())[0]
        print(f"\n=== WRITE #{self.n}: rip=0x{rip:x} newval=0x{v:x} ===")
        if self.n >= 6:
            print("=== enough — stopping ===")
            return True
        return False
W()
end
c
echo \n=== stopped ===\n
x/4i $rip
detach
quit
