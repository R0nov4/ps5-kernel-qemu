target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

# catch the #DF handler right at the register printing (rbx = trap frame)
b *0xffffffff9e7df2db
c

echo \n=== #DF HANDLER CAUGHT (print site) ===\n
info registers rax rbx rcx rdx rsi rdi rbp rsp r12 r13 r14 r15
echo \n=== trap frame fields ===\n
printf "rip  [frame+0xe8] = %p\n", *(unsigned long long *)($rbx + 0xe8)
printf "rsp  [frame+0x100] = %p\n", *(unsigned long long *)($rbx + 0x100)
printf "rbp  [frame+0x40]  = %p\n", *(unsigned long long *)($rbx + 0x40)
printf "rflags? scan frame:\n"
x/40gx $rbx
echo \n=== raw stack (exception frame hunt) ===\n
x/48gx $rsp
echo \n=== gs pcpu ===\n
printf "gs:[0] curthread = %p\n", *(unsigned long long *)($gs_base + 0)
printf "gs:[8] idlethread= %p\n", *(unsigned long long *)($gs_base + 8)
echo \n=== curthread td_pcb / state ===\n
set $td = *(unsigned long long *)($gs_base + 0)
printf "td      = %p\n", $td
printf "td+8    = %p (proc)\n", *(unsigned long long *)($td + 8)
printf "td pcb  = %p\n", *(unsigned long long *)($td + 0x3f8)
printf "td lock = %p\n", *(unsigned long long *)($td)
printf "td state= %d\n", *(int *)($td + 0x400)
echo \n=== thread0 pcb contents (0xa2228a40) ===\n
x/8gx 0xffffffffa2228a40
echo \n=== serial ===\n
shell tail -4 /tmp/w16_serial.log
kill
quit
