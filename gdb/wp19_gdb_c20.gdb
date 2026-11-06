target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9e403e00
b *0xffffffff9ece1f15
c
echo \n=== STOP A ===\n
info registers rip rbx r13 r14
x/gx $r13+$r14+0x20
c
echo \n=== STOP B ===\n
info registers rip rbx r13 r14
x/gx $r13+$r14+0x20
c
echo \n=== STOP C ===\n
info registers rip rbx r13 r14
x/gx $r13+$r14+0x20
c
echo \n=== STOP D ===\n
info registers rip rbx r13 r14
detach
quit
