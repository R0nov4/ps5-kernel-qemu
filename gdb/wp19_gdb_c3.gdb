target remote :1234
set pagination off
set confirm off
b *0xffffffff9e851ac0
b *0xffffffff9e851afe
c
echo \n=== KSTACK ALLOC ENTRY (0x9e851ac0) ===\n
python
import gdb, struct
inf = gdb.selected_inferior()
M = 0xFFFFFFFFFFFFFFFF
for r in ("rdi","rsi","rdx","rcx","r8","rip"):
    print(f"  {r} = 0x{int(gdb.parse_and_eval('$'+r)) & M:x}")
zg = 0xffffffffa190e0c0
zv = struct.unpack("<Q", inf.read_memory(zg, 8).tobytes())[0]
print(f"  kstack-zone [0xa190e0c0] = 0x{zv:x}")
end
c
echo \n=== KSTACK INIT CALL (0x9e851afe: call 0x9e851670) ===\n
python
import gdb
M = 0xFFFFFFFFFFFFFFFF
for r in ("rdi","rsi","rdx","rcx","r8","rip"):
    print(f"  {r} = 0x{int(gdb.parse_and_eval('$'+r)) & M:x}")
end
c
echo \n=== NEXT STOP ===\n
info registers rip rdi rsi rdx rax
bt
detach
quit
