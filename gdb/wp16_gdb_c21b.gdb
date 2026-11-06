target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9eff8c46
c

echo \n=== MALLOC ZONE COMPUTED ===\n
info registers rax rbx rcx rdx rsi rdi r14 r15 r12 r13 rbp
echo \n=== the zone slot (rcx) ===\n
x/6gx $rcx
echo \n=== the zone slot (rsi) ===\n
x/6gx $rsi
echo \n=== serial ===\n
shell tail -2 /tmp/w16_serial.log
kill
quit
