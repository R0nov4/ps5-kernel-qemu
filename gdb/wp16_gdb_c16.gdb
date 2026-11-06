target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e6bb4cc
c

echo \n=== 0x9e6bb4cc CRASH STATE (r13=NULL?) ===\n
info registers rax rbx rcx rdx rsi rdi r12 r13 r14 r15 rbp rsp
echo \n=== stack + frames ===\n
x/32gx $rsp
bt
echo \n=== serial ===\n
shell tail -2 /tmp/w16_serial.log
kill
quit
