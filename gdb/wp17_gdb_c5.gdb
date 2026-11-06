target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

# WP17-C5: the new frontier 0x9e946a00 'mov rdi,[rbx+0x30]'
b *0xffffffff9e946a00 if $rbx > 0 && $rbx < 0x1000
c
echo \n=== CRASH SITE 0x9e946a00 (mov rdi,[rbx+0x30]) ===\n
info registers rax rbx rcx rdx rsi rdi r12 r13 r14 r15 rbp rsp
echo \n=== frame walk ===\n
printf "fr0: rbp=%p  ret=%p\n", $rbp, *(unsigned long long*)($rbp+8)
set $f1 = *(unsigned long long*)($rbp)
printf "fr1: rbp=%p  ret=%p\n", $f1, *(unsigned long long*)($f1+8)
set $f2 = *(unsigned long long*)($f1)
printf "fr2: rbp=%p  ret=%p\n", $f2, *(unsigned long long*)($f2+8)
set $f3 = *(unsigned long long*)($f2)
printf "fr3: rbp=%p  ret=%p\n", $f3, *(unsigned long long*)($f3+8)
set $f4 = *(unsigned long long*)($f3)
printf "fr4: rbp=%p  ret=%p\n", $f4, *(unsigned long long*)($f4+8)
echo \n=== allocator state ===\n
printf "malloc-bump ptr   [0x3F1A0830] = %p\n", *(unsigned long long*)0xffff8e773f1a0830
printf "W1 bump ptr       [0x3F000000] = %p\n", *(unsigned long long*)0xffff8e773f000000
printf "W1 ext base       [0x3F1A0840] = %p\n", *(unsigned long long*)0xffff8e773f1a0840
printf "pool next         [0x3F004008] = %p\n", *(unsigned long long*)0xffff8e773f004008
printf "kmem arena +0x410 (count)      = %d\n", *(int*)0xffffffffa1ab6f00+0x410
echo \n=== serial tail ===\n
shell tail -4 /tmp/w17_serial.log
kill
quit
