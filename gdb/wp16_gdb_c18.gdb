target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e9471ad
c

echo \n=== NULL-ZONE ALLOC CRASH @0x9e9471ad ===\n
info registers rax rbx rcx rdx rsi rdi r12 r13 r14 r15 rbp rsp
echo \n=== the zone (r15) ===\n
x/8gx $r15
echo \n=== frames ===\n
bt
x/24gx $rsp
echo \n=== serial ===\n
shell tail -2 /tmp/w16_serial.log
kill
quit
