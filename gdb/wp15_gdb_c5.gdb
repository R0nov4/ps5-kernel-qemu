target remote :1234
set pagination off
set confirm off
b *0xffffffff9ef8ade3 if (($rcx >> 32) & 0xffffffff) == 0xffffff80
c
echo \n=== LIVE-RESIDUE TABLE CAUGHT ===\n
info registers rax rbx rcx rdx rsi rdi r12 r13 r14 r15 rbp rsp
echo \n=== r13 object (idx*0x140 entry) ===\n
x/8gx $r13+0xc8
echo \n=== r12 array head ===\n
x/8gx $r12
echo \n=== backtrace ===\n
bt
echo \n=== stack ===\n
x/28gx $rsp
kill
quit
