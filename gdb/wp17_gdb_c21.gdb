target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

watch *(unsigned long long*)0xffffffffa19788d8
commands
silent
printf "WITNESS-CELL := %p  rip=%p\n", *(unsigned long long*)0xffffffffa19788d8, $rip
continue
end
c
echo \n=== stopped ===\n
kill
quit
