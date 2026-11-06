target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e81dd69
c
echo \n=== NULL-TABLE CRASH @0x9e81dd69 ===\n
info registers rax rbx rcx rdx rsi rdi r14 r15 rbp rsp
bt
x/20gx $rsp
echo \n=== serial ===\n
shell tail -2 /tmp/w16_serial.log
kill
quit
