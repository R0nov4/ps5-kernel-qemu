target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9ebe1950
c
echo \n=== PANIC PRINTER HIT (the GPF panic path) ===\n
info registers rdi rsi rbp rsp
printf "fr0 ret=%p\n", *(unsigned long long*)($rbp+8)
set $f1 = *(unsigned long long*)($rbp)
printf "fr1 rbp=%p ret=%p\n", $f1, *(unsigned long long*)($f1+8)
set $f2 = *(unsigned long long*)($f1)
printf "fr2 rbp=%p ret=%p\n", $f2, *(unsigned long long*)($f2+8)
set $f3 = *(unsigned long long*)($f2)
printf "fr3 rbp=%p ret=%p\n", $f3, *(unsigned long long*)($f3+8)
set $f4 = *(unsigned long long*)($f3)
printf "fr4 rbp=%p ret=%p\n", $f4, *(unsigned long long*)($f4+8)
echo \n=== big stack window (the trap frame hunt) ===\n
x/64gx $rsp
kill
quit
