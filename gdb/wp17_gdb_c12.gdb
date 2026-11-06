target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e82b933 if $rax > 0 && $rax < 0x1000000
c
echo \n=== BUCKET WALK GARBAGE ===\n
printf "fr0 ret=%p\n", *(unsigned long long*)($rbp+8)
set $f1 = *(unsigned long long*)($rbp)
printf "fr1 rbp=%p ret=%p\n", $f1, *(unsigned long long*)($f1+8)
set $f2 = *(unsigned long long*)($f1)
printf "fr2 rbp=%p ret=%p\n", $f2, *(unsigned long long*)($f2+8)
set $f3 = *(unsigned long long*)($f2)
printf "fr3 rbp=%p ret=%p\n", $f3, *(unsigned long long*)($f3+8)
echo \n=== the zone-global state ===\n
printf "[0xa1ab8440] = %p\n", *(unsigned long long*)0xffffffffa1ab8440
printf "[0xa1e71ea8] = %p\n", *(unsigned long long*)0xffffffffa1e71ea8
printf "[0xa18ea8c0] = %p\n", *(unsigned long long*)0xa18ea8c0
printf "zone(rbx) = %p\n", $rbx
kill
quit
