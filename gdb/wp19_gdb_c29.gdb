target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9e404200
b *0xffffffff9e40422d
c
echo \n=== CAVE93 ENTRY ===\n
info registers rip rdi
x/gx $rdi+0x80
c
echo \n=== NEXT STOP ===\n
info registers rip rdi
x/gx $rdi+0x80
detach
quit
