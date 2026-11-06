target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

# WP16 forensics: catch the cpu_switch call whose newtd (rsi) has NO pcb.
# cpu_switch(oldtd=rdi, newtd=rsi, mtx=rdx) @ 0x9e642160
b *0xffffffff9e642160 if *(unsigned long long *)($rsi + 0x3f8) == 0
c

echo \n=== PCB-LESS SWITCH CAUGHT @ cpu_switch entry ===\n
info registers rdi rsi rdx rbp rsp
echo \n=== newtd identity ===\n
printf "newtd      = %p\n", $rsi
printf "newtd+8    = %p  (td_proc)\n", *(unsigned long long *)($rsi + 8)
printf "newtd pcb  = %p  (td_pcb @+0x3f8 — NULL!)\n", *(unsigned long long *)($rsi + 0x3f8)
printf "newtd lock = %p  (td_lock @+0)\n", *(unsigned long long *)($rsi)
printf "newtd state= %d  ([+0x400])\n", *(int *)($rsi + 0x400)
printf "newtd name = "
x/s *(unsigned long long *)($rsi + 0x5c8)
echo \n=== oldtd (curthread) identity ===\n
printf "oldtd      = %p\n", $rdi
printf "oldtd+8    = %p  (td_proc)\n", *(unsigned long long *)($rdi + 8)
printf "oldtd pcb  = %p\n", *(unsigned long long *)($rdi + 0x3f8)
printf "oldtd lock = %p\n", *(unsigned long long *)($rdi)
printf "oldtd state= %d\n", *(int *)($rdi + 0x400)
printf "oldtd name = "
x/s *(unsigned long long *)($rdi + 0x5c8)
echo \n=== mtx param ===\n
printf "mtx (rdx)  = %p\n", $rdx
echo \n=== backtrace ===\n
bt
echo \n=== stack (return chain) ===\n
x/32gx $rsp
echo \n=== gs pcpu fields ===\n
printf "curthread gs:[0]   = %p\n", *(unsigned long long *)($gs_base + 0)
printf "curpcb    gs:[0x20]= %p\n", *(unsigned long long *)($gs_base + 0x20)
printf "gs:[0x790]         = %p\n", *(unsigned long long *)($gs_base + 0x790)
printf "gs:[0x798]         = %p\n", *(unsigned long long *)($gs_base + 0x798)
echo \n=== serial state ===\n
shell tail -6 /tmp/w16_serial.log
kill
quit
