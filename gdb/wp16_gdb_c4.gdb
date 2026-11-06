target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

# catch the garbage-curthread read: mov rax,[rbx+0x488] with rbx tiny
b *0xffffffff9edfa1c4 if $rbx < 0x10000
c

echo \n=== GARBAGE RBX CAUGHT @0x9edfa1c4 ===\n
info registers rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15
printf "rbx      = %p (curthread from gs:[0])\n", $rbx
printf "gs:[0]   = %p\n", *(unsigned long long *)($gs_base + 0)
printf "gs:[8]   = %p\n", *(unsigned long long *)($gs_base + 8)
printf "gs:[0x34]= %d\n", *(int *)($gs_base + 0x34)
echo \n=== stack ===\n
x/20gx $rsp
echo \n=== backtrace ===\n
bt
echo \n=== serial ===\n
shell tail -3 /tmp/w16_serial.log
kill
quit
