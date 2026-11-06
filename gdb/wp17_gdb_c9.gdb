target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e82b2c3
commands
silent
printf "IMPORT CALL r12=%p zone(rbx)=%p arg=[rbx+0xc0]=%p\n", $r12, $rbx, *(unsigned long long*)($rbx+0xc0)
continue
end
b *0xffffffff9e82b2c9
commands
silent
printf "IMPORT RESULT eax=%d (fail -> designed NULL)\n", $eax
continue
end
b *0xffffffff9ec2d09c
c
echo \n=== CRASH WRITE [rax] = -1 ===\n
printf "rax=%p rbx=%p\n", $rax, $rbx
printf "[0xa1e71ea8] = %p\n", *(unsigned long long*)0xffffffffa1e71ea8
kill
quit
