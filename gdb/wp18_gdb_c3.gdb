target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

# WP18-C3: crash 'mov r15,[rax+0x10]' @0x9f0a162b with rax=NULL
b *0xffffffff9f0a162b if ((unsigned long)$rax) < 0x10000
c
echo \n=== WP18 C3: 0x9f0a162b (mov r15,[rax+0x10]) rax=NULL ===\n
info registers rax rbx rcx rdx rsi rdi r14 r15 rbp rsp
echo \n=== frame walk ===\n
printf "fr0: rbp=%p  ret=[rbp+8]=%p  saved_rbp=[rbp]=%p\n", $rbp, *(unsigned long long*)($rbp+8), *(unsigned long long*)($rbp)
set $f1 = *(unsigned long long*)($rbp)
printf "fr1: rbp=%p  ret=[fr+8]=%p\n", $f1, *(unsigned long long*)($f1+8)
set $f2 = *(unsigned long long*)($f1)
printf "fr2: rbp=%p  ret=[fr+8]=%p\n", $f2, *(unsigned long long*)($f2+8)
set $f3 = *(unsigned long long*)($f2)
printf "fr3: rbp=%p  ret=[fr+8]=%p\n", $f3, *(unsigned long long*)($f3+8)
echo \n=== stack window ===\n
x/20gx $rsp
kill
quit
