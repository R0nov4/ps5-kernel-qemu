target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9ecd01a0
c
echo \n=== CALL 1 ===\n
info registers rdi rsi rdx rcx
c
echo \n=== CALL 2 ===\n
info registers rdi rsi rdx rcx
c
echo \n=== CALL 3 ===\n
info registers rdi rsi rdx rcx
c
echo \n=== CALL 4 ===\n
info registers rdi rsi rdx rcx
detach
quit
