target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e84d990
c

echo \n=== 0xffffff80-RESIDUE CRASH ===\n
info registers rax rbx rcx rdx rsi rdi r14 r15 rbp rsp
printf "rax = %p (the residue ptr!)\n", $rax
echo \n=== the source global [0xa190b808] ===\n
x/4gx 0xffffffffa190b808
echo \n=== frames ===\n
bt
x/24gx $rsp
echo \n=== serial ===\n
shell tail -2 /tmp/w16_serial.log
kill
quit
