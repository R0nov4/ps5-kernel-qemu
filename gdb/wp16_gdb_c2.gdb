target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

# WP16 test#2 forensics: which context path runs (cpu_switch vs cpu_throw)?
b *0xffffffff9e642150
b *0xffffffff9e400e80
c

echo \n=== FIRST CONTEXT-PATH HIT ===\n
printf "pc = %p\n", $pc
info registers rdi rsi rdx rbx r12 r13 r15 rbp rsp
echo \n=== newtd (rsi) identity ===\n
printf "newtd      = %p\n", $rsi
printf "newtd pcb  = %p\n", *(unsigned long long *)($rsi + 0x3f8)
printf "newtd+8    = %p (td_proc)\n", *(unsigned long long *)($rsi + 8)
echo \n=== oldtd (rdi) identity ===\n
printf "oldtd      = %p\n", $rdi
printf "oldtd pcb  = %p\n", *(unsigned long long *)($rdi + 0x3f8)
echo \n=== thread0 pcb contents (0xa2228a40) ===\n
x/8gx 0xffffffffa2228a40
echo \n=== gs pcpu ===\n
printf "gs:[0] curthread = %p\n", *(unsigned long long *)($gs_base + 0)
printf "gs:[8] idlethread= %p\n", *(unsigned long long *)($gs_base + 8)
printf "gs:[0x34] cpuid  = %d\n", *(int *)($gs_base + 0x34)
echo \n=== backtrace ===\n
bt
echo \n=== stack ===\n
x/24gx $rsp
echo \n=== serial state ===\n
shell tail -4 /tmp/w16_serial.log
kill
quit
