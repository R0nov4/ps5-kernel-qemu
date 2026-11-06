target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9e851681 if ((unsigned long)$rdx) < 0x10000
c
echo \n=== WP18 C10: 0x9e851681 (mov [rdx+0x68],0) rdx=NULL ===\n
info registers rax rbx rcx rdx rsi rdi r8 r9 rbp rsp
printf "fr0: rbp=%p  ret=[rbp+8]=%p\n", $rbp, *(unsigned long long*)($rbp+8)
set $f1 = *(unsigned long long*)($rbp)
printf "fr1: rbp=%p  ret=[fr+8]=%p\n", $f1, *(unsigned long long*)($f1+8)
set $f2 = *(unsigned long long*)($f1)
printf "fr2: rbp=%p  ret=[fr+8]=%p\n", $f2, *(unsigned long long*)($f2+8)
x/10gx $rsp
kill
quit
