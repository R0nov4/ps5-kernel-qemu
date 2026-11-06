target remote :1234
set pagination off
set confirm off
b *0xffffffff9e851681
b *0xffffffff9e92a634
b *0xffffffff9e92a688
c
python
import gdb
M = 0xFFFFFFFFFFFFFFFF
rip = int(gdb.parse_and_eval("$rip")) & M
print(f"\n=== STOP 1 @ 0x{rip:x} ===")
for r in ("rdi","rsi","rdx","rcx","rax","r12","r13","r15"):
    print(f"  {r} = 0x{int(gdb.parse_and_eval('$'+r)) & M:x}")
end
c
python
import gdb
M = 0xFFFFFFFFFFFFFFFF
rip = int(gdb.parse_and_eval("$rip")) & M
print(f"\n=== STOP 2 @ 0x{rip:x} ===")
for r in ("rdi","rsi","rdx","rcx","rax","r12","r13","r15"):
    print(f"  {r} = 0x{int(gdb.parse_and_eval('$'+r)) & M:x}")
end
c
python
import gdb
M = 0xFFFFFFFFFFFFFFFF
rip = int(gdb.parse_and_eval("$rip")) & M
print(f"\n=== STOP 3 @ 0x{rip:x} ===")
for r in ("rdi","rsi","rdx","rcx","rax","r12","r13","r15"):
    print(f"  {r} = 0x{int(gdb.parse_and_eval('$'+r)) & M:x}")
end
detach
quit
