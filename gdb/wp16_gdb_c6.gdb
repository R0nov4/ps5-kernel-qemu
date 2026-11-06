target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

# catch the NULL r13 write at 0x9ef7a475
b *0xffffffff9ef7a475 if $r13 < 0x1000
c

echo \n=== NULL r13 WRITE CAUGHT @0x9ef7a475 ===\n
info registers rax rbx rcx rdx rsi rdi r13 r14 rbp rsp
echo \n=== the alloc call result (0x9ea05730 = 0x9ef7a43c call) ===\n
printf "r13 = alloc result = %p\n", $r13
echo \n=== backtrace ===\n
bt
echo \n=== stack ===\n
x/32gx $rsp
echo \n=== serial ===\n
shell tail -3 /tmp/w16_serial.log
kill
quit
