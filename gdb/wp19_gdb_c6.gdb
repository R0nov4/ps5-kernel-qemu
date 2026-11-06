target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9e7de0e0
c
echo \n=== TRAP CAUGHT (frozen-start bp) ===\n
info registers rdi rsi rdx rax rbx rip rsp
python
import gdb, struct
inf = gdb.selected_inferior()
M = 0xFFFFFFFFFFFFFFFF
rdi = int(gdb.parse_and_eval("$rdi")) & M
print(f"trapframe @ 0x{rdi:x}")
fr = inf.read_memory(rdi, 0x120).tobytes()
vals = struct.unpack("<24Q", fr[:0xc0])
names = ["rdi","rsi","rdx","rcx","r8","r9","rax","rbx","rbp","r10","r11","r12","r13","r14","r15","+78","+80","+88","+90","+98","+a0","+a8","+b0","+b8"]
for n, v in zip(names, vals):
    print(f"  tf_{n} = 0x{v:x}")
tno = struct.unpack("<I", fr[0x78:0x7c])[0]
err = struct.unpack("<I", fr[0x7c:0x80])[0]
rip = vals[19]
print(f"  trapno = {tno}  err = 0x{err:x}")
rbp = vals[8]
print(f"--- crash-time rbp chain from tf_rbp=0x{rbp:x} ---")
f = rbp
for i in range(16):
    try:
        saved, ret = struct.unpack("<QQ", inf.read_memory(f, 16).tobytes())
        print(f"frame {i}: rbp=0x{f:x} ret=0x{ret:x}")
        if saved == 0 or (saved & 0xFF000000000000) != (f & 0xFF000000000000): break
        f = saved & M
    except Exception as e:
        print(f"frame {i}: err {e}"); break
print("\n=== bump-window cursor ===")
cur = struct.unpack("<Q", inf.read_memory(0xFFFF8E773F1A0830, 8).tobytes())[0]
print(f"cursor = 0x{cur:016x}")
end
detach
quit
