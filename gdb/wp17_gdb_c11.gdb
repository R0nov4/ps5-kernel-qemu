target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e82b933 if $rax > 0 && $rax < 0x1000000
c
echo \n=== BUCKET WALK GARBAGE: rax ===\n
info registers rax rbx r14 r12 rbp rdi
echo \n=== the zone (rbx) fields ===\n
printf "zone=%p  [zone+0x40]=%p [zone+0x60]=%p [zone+0x68]=%p\n", $rbx, *(unsigned long long*)($rbx+0x40), *(unsigned long long*)($rbx+0x60), *(unsigned long long*)($rbx+0x68)
echo \n=== the bucket slot (r14) ===\n
x/4gx $r14
echo \n=== the bucket object (r12 = [r14]) ===\n
x/4gx $r12
echo \n=== frame walk ===\n
printf "fr0 ret=%p\n", *(unsigned long long*)($rbp+8)
set $f1 = *(unsigned long long*)($rbp)
printf "fr1 rbp=%p ret=%p\n", $f1, *(unsigned long long*)($f1+8)
set $f2 = *(unsigned long long*)($f1)
printf "fr2 rbp=%p ret=%p\n", $f2, *(unsigned long long*)($f2+8)
shell tail -3 /tmp/w17_serial.log
kill
quit
