target remote :1234
set pagination off
set confirm off
# catch the bad-array-base deref (r15 not a DMAP pointer)
b *0xffffffff9ea05663 if $r15 < 0x800000000000
c
echo \n=== BAD BASE CAUGHT ===\n
info registers rax rbx rcx rdx rsi rdi r12 r13 r14 r15 rbp rsp
echo \n=== the bucket r12 ===\n
x/6gx $r12
echo \n=== m (r14) ===\n
x/16gx $r14
echo \n=== backtrace ===\n
bt
echo \n=== stack ===\n
x/24gx $rsp
kill
quit
