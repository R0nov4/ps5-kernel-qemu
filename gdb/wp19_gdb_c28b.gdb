target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
watch *(unsigned long *)0xffff8e77222d9fa8
c
echo \n=== W1 ===\n
info registers rip rbx rax
x/4i $rip-10
c
echo \n=== W2 ===\n
info registers rip rbx rax
x/4i $rip-10
c
echo \n=== W3 ===\n
info registers rip rbx rax
x/4i $rip-10
detach
quit
