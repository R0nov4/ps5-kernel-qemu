target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e8b76da if $r15 > 0x7fffffffffff && $r15 < 0xffff800000000000
c
echo \n=== GPF SITE: r15 non-canonical ===\n
info registers r15 rdi rsi rbp rsp rbx r14 r13
printf "fr0 ret=%p\n", *(unsigned long long*)($rbp+8)
set $f1 = *(unsigned long long*)($rbp)
printf "fr1 rbp=%p ret=%p\n", $f1, *(unsigned long long*)($f1+8)
set $f2 = *(unsigned long long*)($f1)
printf "fr2 rbp=%p ret=%p\n", $f2, *(unsigned long long*)($f2+8)
set $f3 = *(unsigned long long*)($f2)
printf "fr3 rbp=%p ret=%p\n", $f3, *(unsigned long long*)($f3+8)
x/24gx $rsp
kill
quit
