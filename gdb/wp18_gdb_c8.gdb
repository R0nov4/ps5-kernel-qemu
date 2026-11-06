target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64
b *0xffffffff9ee40ffd if ((unsigned long)$rbx) < 0x10000
c
echo \n=== WP18 C8: 0x9ee40ffd (mov rsi,[rbx+0x118]) rbx=NULL ===\n
info registers rax rbx rcx rdx rsi rdi rbp rsp
printf "fr0: rbp=%p  ret=[rbp+8]=%p\n", $rbp, *(unsigned long long*)($rbp+8)
set $f1 = *(unsigned long long*)($rbp)
printf "fr1: rbp=%p  ret=[fr+8]=%p\n", $f1, *(unsigned long long*)($f1+8)
set $f2 = *(unsigned long long*)($f1)
printf "fr2: rbp=%p  ret=[fr+8]=%p\n", $f2, *(unsigned long long*)($f2+8)
set $f3 = *(unsigned long long*)($f2)
printf "fr3: rbp=%p  ret=[fr+8]=%p\n", $f3, *(unsigned long long*)($f3+8)
x/12gx $rsp
kill
quit
