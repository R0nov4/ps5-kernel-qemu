set pagination off
set confirm off
set architecture i386:x86-64
set remotetimeout 600
target remote localhost:1234
break *0xffffffff9e642a90
watch *(unsigned long long*)0xffff8e77000ac000
continue
printf "\n=== stop: btext ===\n"
continue
printf "\n=== PD 0xac000 FIRST WRITE caught ===\n"
info registers rip rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15
printf "\n=== code around RIP ===\n"
x/12i $rip-24
printf "\n=== value written check ===\n"
x/4gx 0xffff8e77000ac000
kill
quit
