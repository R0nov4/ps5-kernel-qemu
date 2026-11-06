target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9eef4158
c
echo \n=== LINKED-LIST WALK NULL @0x9eef4158 ===\n
info registers rax rbx rcx rdx rsi rdi r8 r9 r12 r13 r14 r15 rbp rsp
echo \n=== frames ===\n
bt
x/24gx $rsp
echo \n=== serial ===\n
shell tail -2 /tmp/w16_serial.log
kill
quit
