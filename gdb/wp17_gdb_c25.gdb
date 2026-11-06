target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

watch *(unsigned long long*)0xffffffff9febae18
commands
silent
printf "UNLOCK-FLAG := %p  rip=%p\n", *(unsigned long long*)0xffffffff9febae18, $rip
continue
end
b *0xffffffff9e8b71bc if $rdi > 0 && $rdi < 0x1000
c
echo \n=== CRASH ===\n
kill
quit
