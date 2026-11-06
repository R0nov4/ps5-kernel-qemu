target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e6bb1df
c

echo \n=== INNER REGION ALLOC THUNK CALL ===\n
printf "thunk r12 = %p\n", *(unsigned long long *)($r12 + 0x428)
info registers rax rbx rcx rdx rsi rdi r12 r13 r14 rbp rsp
echo \n=== r12 (the arena obj) fields ===\n
x/8gx $r12
echo \n=== serial ===\n
shell tail -2 /tmp/w16_serial.log
kill
quit
