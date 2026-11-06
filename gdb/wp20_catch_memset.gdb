target remote :1234
set pagination off
set confirm off
break *0xffffffff9e648ff0 if $rdi == 0 && $rsi > 0
continue
echo \n=== HIT memset(NULL, len>0) ===\n
info registers rdi rsi rbp rsp rip
echo \n=== RBP CHAIN ===\n
python
import gdb, struct
inf = gdb.selected_inferior()
rsp = int(gdb.parse_and_eval("$rsp"))
rbp = int(gdb.parse_and_eval("$rbp"))
print(f"ret@rsp = 0x{struct.unpack('<Q', inf.read_memory(rsp, 8).tobytes())[0]:016x}")
f = rbp
for i in range(24):
    try:
        frame = inf.read_memory(f, 16).tobytes()
        saved_rbp, ret = struct.unpack("<QQ", frame)
        print(f"frame {i}: rbp=0x{f:016x} ret=0x{ret:016x}")
        if saved_rbp == 0 or saved_rbp < 0x1000 or (saved_rbp >> 40) != (f >> 40):
            break
        f = saved_rbp
    except Exception as e:
        print(f"frame {i}: err {e}")
        break
end
detach
quit
