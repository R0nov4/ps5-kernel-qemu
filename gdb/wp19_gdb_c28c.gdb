target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
watch *(unsigned long *)0xffff8e77222d9fa8
set $mine = 0
c
echo \n=== W1 ===\n
info registers rip
c
echo \n=== W2 ===\n
info registers rip
c
echo \n=== W3 ===\n
info registers rip
c
echo \n=== W4 ===\n
info registers rip
c
echo \n=== W5 ===\n
info registers rip
c
echo \n=== W6 ===\n
info registers rip
detach
quit
