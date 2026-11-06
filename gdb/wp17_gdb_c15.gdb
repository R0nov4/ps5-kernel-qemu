target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9eff8c6b if $rsi > 0xffffffffa0fec000
c
echo \n=== THE BAD ZONE LOOKUP ===\n
printf "rsi (entry slot)=%p  rax (byte index)=%d  ecx (class*16)=%d\n", $rsi, $rax, $ecx
printf "the loaded zone = %p\n", $rbx
printf "malloc rbp=%p  [rbp-0x40] (ctx) = %p\n", $rbp, *(unsigned long long*)($rbp-0x40)
set $ctx = *(unsigned long long*)($rbp-0x40)
printf "ctx=%p  ctx+8..+0x30:\n", $ctx
x/7gx $ctx
echo \n=== the size registers at the lookup ===\n
info registers r14 r13d r12d r15
echo \n=== frame ===\n
printf "fr0 ret=%p\n", *(unsigned long long*)($rbp+8)
set $f1 = *(unsigned long long*)($rbp)
printf "fr1 rbp=%p ret=%p\n", $f1, *(unsigned long long*)($f1+8)
kill
quit
