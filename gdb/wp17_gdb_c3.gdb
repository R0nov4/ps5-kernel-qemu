target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

# WP17-C3: catch the unbalanced unlock at its panic site
b *0xffffffff9e8b70b9
c
echo \n=== UNLOCK-PANIC SITE 0x9e8b70b9 (__mtx_unlock_flags: td_locks) ===\n
info registers rdi rbx r12 r14 r15 rbp rsp
printf "td_locks = %d\n", *(short*)($rbx + 0x10a)
echo \n=== the lock object (rdi = the lock word; base = rdi-0x18) ===\n
x/8gx $rdi - 0x18
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
echo \n=== stack window ===\n
x/32gx $rsp
echo \n=== serial tail ===\n
shell tail -5 /tmp/w17_serial.log
kill
quit
