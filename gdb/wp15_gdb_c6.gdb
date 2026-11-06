target remote :1234
set pagination off
set confirm off
b *0xffffffff9e8b726e
b *0xffffffff9e8b79ac
c
echo \n=== SPIN TIMEOUT ASSERT CAUGHT ===\n
info registers rax rbx rcx rdx rsi rdi r11 r12 r13 r14 r15 rbp rsp
echo \n=== the lock 0xffffffffa2229cc0 ===\n
x/8gx 0xffffffffa2229cc0
echo \n=== stack around ===\n
x/40gx $rsp
echo \n=== try backtrace ===\n
bt
kill
quit
