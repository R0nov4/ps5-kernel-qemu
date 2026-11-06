target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e81d5e8
commands
silent
printf "WITNESS-READ: [thread0+0x78] = %p  rip=%p\n", *(unsigned long long*)0xffffffffa19788d8, $rip
continue
end
b *0xffffffff9e8b71bc if $rdi > 0 && $rdi < 0x1000
c
echo \n=== CRASH STATE ===\n
printf "[thread0+0x78] = %p\n", *(unsigned long long*)0xffffffffa19788d8
info registers rdi r14 r15 rbp
kill
quit
