target remote :1234
set pagination off
set confirm off
b *0xffffffff9f00ae7c if $rdi == 0
c
echo \n=== NULL SQ CAUGHT ===\n
info registers rax rbx rcx rdx rsi rdi r12 r13 r14 r15 rbp rsp
echo \n=== rsi (thread?) ===\n
x/8gx $rsi
echo \n=== backtrace ===\n
bt
echo \n=== stack ===\n
x/32gx $rsp
kill
quit
