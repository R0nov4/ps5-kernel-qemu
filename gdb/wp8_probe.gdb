set architecture i386:x86-64
target remote localhost:1234
break *0xffffffff9ef7a475
continue
echo \n=== WP8 PROBE: hit 0x9ef7a475 ===\n
info registers rax rbx rcx rdx rsi rdi rbp rsp r12 r13 r14 r15
echo \n=== being_run @ 0xffffffffa19781b0 ===\n
x/gx 0xffffffffa19781b0
echo \n=== sysinit element (deref being_run) ===\n
set $br = *(unsigned long *)0xffffffffa19781b0
x/5gx $br
echo \n=== mi_startup end-global @ 0xffffffffa19781a8 ===\n
x/gx 0xffffffffa19781a8
echo \n=== bootverbose @ 0xffffffffa1978858 ===\n
x/gx 0xffffffffa1978858
echo \n=== profile[0] runtime @ 0xffffffffa1925ea0 ===\n
x/17gx 0xffffffffa1925ea0
echo \n=== dump-state globals (crash2/3 sites) ===\n
x/gx 0xffffffffa1fdf3c0
x/gx 0xffffffffa21fb420
echo \n=== stack 64 qwords from rsp ===\n
x/64gx $rsp
echo \n=== msgbufp / gate ===\n
x/gx 0xffffffffa1fb8a60
x/gx 0xffffffffa1926628
detach
quit
