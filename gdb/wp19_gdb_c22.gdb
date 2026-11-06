target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9e403e46
b *0xffffffff9e403e4e
b *0xffffffff9ece1f15
b *0xffffffff9ece1e3a
c
echo \n=== S1 ===\n
info registers rip rbx rax
c
echo \n=== S2 ===\n
info registers rip rbx rax
c
echo \n=== S3 ===\n
info registers rip rbx rax
c
echo \n=== S4 ===\n
info registers rip rbx rax
detach
quit
