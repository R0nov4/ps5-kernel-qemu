target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

# catch the ACTUAL crash: the #PF handler print site (rbx = trap frame)
b *0xffffffff9e7df2db
# AND the garbage-rbx load site, exactly the crash value
b *0xffffffff9edfa1c4 if $rbx == 0x101
c

echo \n=== CAUGHT ===\n
printf "pc = %p\n", $pc
info registers rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15
echo \n=== if at 0x9edfa1c4: dump gs + curthread area ===\n
printf "gs:[0]   = %p\n", *(unsigned long long *)($gs_base + 0)
printf "gs:[8]   = %p\n", *(unsigned long long *)($gs_base + 8)
printf "gs:[0x34]= %d\n", *(int *)($gs_base + 0x34)
echo \n=== stack ===\n
x/24gx $rsp
echo \n=== serial ===\n
shell tail -3 /tmp/w16_serial.log
kill
quit
