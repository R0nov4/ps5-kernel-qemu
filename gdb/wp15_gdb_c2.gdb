target remote :1234
set pagination off
set confirm off
# fmtB assert sites (only reached when the queue check FAILS = our panic)
b *0xffffffff9e7be914
b *0xffffffff9e85eee8
b *0xffffffff9ea05c8d
b *0xffffffff9ea82817
b *0xffffffff9ea83ee0
b *0xffffffff9ea83f17
b *0xffffffff9ea8415b
b *0xffffffff9ea84199
b *0xffffffff9ea843f1
b *0xffffffff9ea8442f
b *0xffffffff9eb3091c
b *0xffffffff9eb30a80
b *0xffffffff9ef7c2fb
b *0xffffffff9ef7c3f0
b *0xffffffff9ef7c511
b *0xffffffff9ef7c60b
c
echo \n=== ASSERT SITE HIT ===\n
info registers rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r12 r13 r14 r15
echo \n=== backtrace ===\n
bt
echo \n=== queue state: around elm 0xffff8e773f0100f0 ===\n
x/8gx 0xffff8e773f0100d0
echo \n=== around next 0xffff8e773f000000 ===\n
x/16gx 0xffff8e773f000000
echo \n=== stack ===\n
x/32gx $rsp
kill
quit
