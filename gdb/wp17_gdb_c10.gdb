target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e8b6a2d if $rdi > 0 && $rdi < 0x1000
c
echo \n=== MTX_LOCK NULL-site: rdi ===\n
info registers rdi rsi rbp rsp rbx
echo \n=== frame walk ===\n
printf "fr0: rbp=%p ret=%p\n", $rbp, *(unsigned long long*)($rbp+8)
set $f1 = *(unsigned long long*)($rbp)
printf "fr1: rbp=%p ret=%p\n", $f1, *(unsigned long long*)($f1+8)
set $f2 = *(unsigned long long*)($f1)
printf "fr2: rbp=%p ret=%p\n", $f2, *(unsigned long long*)($f2+8)
set $f3 = *(unsigned long long*)($f2)
printf "fr3: rbp=%p ret=%p\n", $f3, *(unsigned long long*)($f3+8)
echo \n=== stack ===\n
x/16gx $rsp
shell tail -3 /tmp/w17_serial.log
kill
quit
