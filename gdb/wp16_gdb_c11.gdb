target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

# catch the panic printf chain: break at the panic-message print (0x9e8f3d29)
b *0xffffffff9e8f3d29
c

echo \n=== PANIC PRINT CAUGHT — walk back to the fault ===\n
info registers rbx rbp rsp r12 r13 r14 r15
echo \n=== stack ===\n
x/48gx $rsp
echo \n=== serial ===\n
shell tail -3 /tmp/w16_serial.log
kill
quit
