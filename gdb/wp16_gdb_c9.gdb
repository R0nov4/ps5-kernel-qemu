target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

# breakpoints on all the td_locks-assert print sites (panic-path-only leas)
b *0xffffffff9e8b6e33
b *0xffffffff9e8b6e78
b *0xffffffff9e8b70e3
b *0xffffffff9e8b711b
b *0xffffffff9e8b7804
b *0xffffffff9e8b7f16
b *0xffffffff9ebc4ae2
b *0xffffffff9ebc4bb7
b *0xffffffff9ebc4bf3
b *0xffffffff9ebc4e7b
b *0xffffffff9ebc5023
b *0xffffffff9ebc505b
b *0xffffffff9ebc5b8e
b *0xffffffff9eeb17c3
b *0xffffffff9eeb17fb
b *0xffffffff9eeb1985
b *0xffffffff9eeb19bd
c

echo \n=== TD_LOCKS ASSERT HIT ===\n
printf "pc = %p\n", $pc
info registers rax rbx rcx rdx rsi rdi rbp rsp r12 r13 r14 r15
echo \n=== the lock object (rdi typically) ===\n
x/6gx $rdi
echo \n=== backtrace ===\n
bt
echo \n=== stack ===\n
x/32gx $rsp
echo \n=== serial ===\n
shell tail -3 /tmp/w16_serial.log
kill
quit
