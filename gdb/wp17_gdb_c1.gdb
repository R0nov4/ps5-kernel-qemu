target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

# WP17-C1: stop at the faulting instruction 'mov r15,[rdi+0x98]' BEFORE it faults
b *0xffffffff9e82b788 if $rdi < 0x1000
c
echo \n=== WP17 C1: CRASH SITE 0x9e82b788 (mov r15,[rdi+0x98]) ===\n
info registers rax rbx rcx rdx rsi rdi r12 r13 r14 r15 rbp rsp
echo \n=== frame walk from rbp ===\n
printf "fr0: rbp=%p  ret=[rbp+8]=%p  saved_rbp=[rbp]=%p\n", $rbp, *(unsigned long long*)($rbp+8), *(unsigned long long*)($rbp)
set $f1 = *(unsigned long long*)($rbp)
printf "fr1: rbp=%p  ret=[fr+8]=%p  saved_rbp=[fr]=%p\n", $f1, *(unsigned long long*)($f1+8), *(unsigned long long*)($f1)
set $f2 = *(unsigned long long*)($f1)
printf "fr2: rbp=%p  ret=[fr+8]=%p  saved_rbp=[fr]=%p\n", $f2, *(unsigned long long*)($f2+8), *(unsigned long long*)($f2)
set $f3 = *(unsigned long long*)($f2)
printf "fr3: rbp=%p  ret=[fr+8]=%p  saved_rbp=[fr]=%p\n", $f3, *(unsigned long long*)($f3+8), *(unsigned long long*)($f3)
set $f4 = *(unsigned long long*)($f3)
printf "fr4: rbp=%p  ret=[fr+8]=%p\n", $f4, *(unsigned long long*)($f4+8)
echo \n=== stack window around rsp ===\n
x/48gx $rsp
echo \n=== arg2 (r14) object probe ===\n
x/8gx $r14
echo \n=== vm_reserv counter @0xa1d0c310 ===\n
x/1gx 0xffffffffa1d0c310
echo \n=== serial tail ===\n
shell tail -6 /tmp/w17_serial.log
kill
quit
