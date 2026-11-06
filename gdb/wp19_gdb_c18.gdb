target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9ecd01a0
c
python
import gdb, struct
inf = gdb.selected_inferior()
M = 0xFFFFFFFFFFFFFFFF
print(f"\n=== PT-FILL FN 0x9ecd01a0 called ===")
for r in ("rdi","rsi","rdx","rcx","r14","r13"):
    print(f"  {r} = 0x{int(gdb.parse_and_eval('$'+r)) & M:x}")
end
c
python
import gdb, struct
inf = gdb.selected_inferior()
M = 0xFFFFFFFFFFFFFFFF
print(f"\n=== STOP 2 rip=0x{int(gdb.parse_and_eval('$rip')) & M:x} ===")
for r in ("rdi","rsi","rdx","rcx"):
    print(f"  {r} = 0x{int(gdb.parse_and_eval('$'+r)) & M:x}")
end
detach
quit
