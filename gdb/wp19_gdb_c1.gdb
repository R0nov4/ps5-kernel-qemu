target remote :1234
set pagination off
set confirm off
b *0xffffffff9ebc46a0 if $rdi < 0x100000
c
echo \n=== CRASH CALLER CAUGHT (mtx_lock with bogus rdi) ===\n
info registers rdi rsi rax rbx rbp rsp rip
echo \n=== rbp chain ===\n
python
import gdb, struct
inf = gdb.selected_inferior()
rbp = int(gdb.parse_and_eval("$rbp"))
rip = int(gdb.parse_and_eval("$rip"))
print(f"RIP=0x{rip:x} RBP=0x{rbp:x}")
f = rbp
for i in range(14):
    try:
        saved, ret = struct.unpack("<QQ", inf.read_memory(f, 16).tobytes())
        print(f"frame {i}: rbp=0x{f:x} ret=0x{ret:x}")
        if saved == 0 or (saved >> 40) != (f >> 40): break
        f = saved
    except Exception as e:
        print(f"frame {i}: err {e}"); break
end
x/8i $rip
detach
quit
