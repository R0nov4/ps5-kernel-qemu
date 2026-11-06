target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e8f3d03
c

echo \n=== KMEM_SUBALLOC FAIL CAUGHT (ebx = status) ===\n
info registers rax rbx rcx rdx rsi rdi r12 r13 r14 r15 rbp rsp
echo \n=== backtrace ===\n
bt
echo \n=== stack ===\n
x/40gx $rsp
echo \n=== serial ===\n
shell tail -3 /tmp/w16_serial.log
kill
quit
