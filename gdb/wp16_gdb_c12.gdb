target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

# catch the faulting access: read/execute near DMAP(0x3F300000)
awatch *0xffff8e773f300000
c
echo \n=== W6-HEAD WATCHPOINT HIT ===\n
printf "pc = %p\n", $pc
info registers rax rbx rcx rdx rsi rdi rbp rsp
x/6i $pc
echo \n=== backtrace ===\n
bt
echo \n=== serial ===\n
shell tail -2 /tmp/w16_serial.log
kill
quit
