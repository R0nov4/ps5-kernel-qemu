set pagination off
set confirm off
set architecture i386:x86-64
set remotetimeout 600
target remote localhost:1234
break *0xffffffff9e642a90
break *0xffffffff9ece3550
continue
printf "\n=== stop 1 (btext) ===\n"
continue
printf "\n=== search fn 0x9ece3550 ENTRY (before crash insn) ===\n"
info registers rdi rsi rdx rcx r8 r9 rbx r12 r13 r14 r15
printf "caller = %p\n", *(unsigned long long*)($rbp+8)
printf "args: rdi=%p rsi=%p\n", $rdi, $rsi
printf "rdi target struct (if mapped):\n"
x/4gx $rdi
printf "\n=== stack walk for return addrs ===\n"
x/32gx $rsp
kill
quit
