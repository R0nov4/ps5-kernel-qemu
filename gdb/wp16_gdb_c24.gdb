target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e9d7040
c
echo \n=== WAITING-ALLOC PANIC CAUGHT ===\n
info registers rax rbx rcx rdx rsi rdi r12 r13 r14 r15 rbp rsp
echo \n=== frames ===\n
bt
x/24gx $rsp
echo \n=== serial ===\n
shell tail -3 /tmp/w16_serial.log
kill
quit
