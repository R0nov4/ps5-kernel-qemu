target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

# WP18-C1: the refcount crash 'lock add [rdi+8],1' @0x9ec2c374 with rdi=NULL
b *0xffffffff9ec2c374 if $rdi < 0x1000
c
echo \n=== WP18 C1: refcount site 0x9ec2c374 (lock add [rdi+8],1) rdi=NULL ===\n
info registers rax rbx rcx rdx rsi rdi r8 r9 r12 r13 r14 r15 rbp rsp
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
set $f5 = *(unsigned long long*)($f4)
printf "fr5: rbp=%p  ret=[fr+8]=%p\n", $f5, *(unsigned long long*)($f5+8)
echo \n=== stack window around rsp ===\n
x/24gx $rsp
kill
quit
