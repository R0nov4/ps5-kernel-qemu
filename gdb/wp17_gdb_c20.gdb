target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e8b71bc if $rdi > 0 && $rdi < 0x1000
c
echo \n=== UNLOCK NULL-SITE 0x9e8b71bc ===\n
info registers rdi rsi r14 r15 rbx r12 rbp rsp
printf "fr0 ret=%p\n", *(unsigned long long*)($rbp+8)
set $f1 = *(unsigned long long*)($rbp)
printf "fr1 rbp=%p ret=%p\n", $f1, *(unsigned long long*)($f1+8)
set $f2 = *(unsigned long long*)($f1)
printf "fr2 rbp=%p ret=%p\n", $f2, *(unsigned long long*)($f2+8)
set $f3 = *(unsigned long long*)($f2)
printf "fr3 rbp=%p ret=%p\n", $f3, *(unsigned long long*)($f3+8)
kill
quit
