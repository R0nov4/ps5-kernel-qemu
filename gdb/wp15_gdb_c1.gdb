target remote :1234
set pagination off
set confirm off
# catch the crashing call: rcx (domain block array) == 0 right after load
b *0xffffffff9e945c0c if $rcx == 0
c
echo \n=== CRASH CALL CAUGHT ===\n
info registers rdi rcx rdx rax rbp rsp
echo \n=== backtrace ===\n
bt
echo \n=== vm_page (rdi) ===\n
x/16gx $rdi
echo \n=== vm_dom array @0xa197a3d0 ===\n
x/24gx 0xffffffffa197a3d0
echo \n=== domain byte [rdi+0x6b] ===\n
x/1xb $rdi+0x6b
echo \n=== caller frames on stack ===\n
x/24gx $rsp
kill
quit
