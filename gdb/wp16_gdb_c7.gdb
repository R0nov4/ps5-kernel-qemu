target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

# catch the W1 exhaustion
b *0xffffffff9ee3013e
c

echo \n=== W1 EXHAUSTION CAUGHT ===\n
info registers rax rcx rdx r13 r14 rbp rsp
printf "bump ptr (rcx) = %#lx\n", $rcx
echo \n=== caller frames (vm_page_startup loop) ===\n
x/40gx $rsp
echo \n=== current loop counters from rbp ===\n
x/16gx $rbp
echo \n=== serial ===\n
shell tail -3 /tmp/w16_serial.log
kill
quit
