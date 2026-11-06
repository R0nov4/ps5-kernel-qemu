target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
watch *(unsigned long *)0xffffffffa1f37eb0
c
echo \n=== W1 ===\n
info registers rip rbx r15
x/4i $rip-10
c
echo \n=== W2 ===\n
info registers rip rbx r15
x/4i $rip-10
c
echo \n=== W3 ===\n
info registers rip rbx r15
x/4i $rip-10
c
echo \n=== W4 ===\n
info registers rip rbx r15
x/4i $rip-10
detach
quit
