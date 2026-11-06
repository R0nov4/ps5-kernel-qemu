target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9e403e00
c
echo \n=== CAVE ENTRY ===\n
x/24i 0xffffffff9e403e00
echo \n=== head value ===\n
x/gx $r13+$r14+0x20
si
echo \n=== after insn 1 ===\n
info registers rbx rax rip
si
si
si
echo \n=== stepping ===\n
info registers rbx rax rip
si
si
si
si
si
si
echo \n=== more ===\n
info registers rbx rax rip
x/3i $rip
detach
quit
