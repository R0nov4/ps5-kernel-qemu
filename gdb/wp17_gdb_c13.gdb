target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9eff8c6b if $rsi > 0xffffffffa0feb8d0 && $rsi < 0xffffffffa0fec510
c
echo \n=== MALLOC ZONE LOOKUP (the crashing one) ===\n
printf "rbx (the type's zone table [ctx+0x18]) = %p\n", $rbx
printf "rax (the byte [rbx+8]) = %d\n", $rax
printf "ecx (class*16) = %d  rsi (entry addr) = %p\n", $ecx, $rsi
printf "the zone = [rsi+rax*8] = %p\n", *(unsigned long long*)($rsi + $rax*8)
echo \n=== the ctx (r15) and its fields ===\n
printf "r15 (ctx) = %p  [ctx+0x18] (the table) = %p\n", $r15, *(unsigned long long*)($r15+0x18)
x/6gx $r15
echo \n=== the size (r14 at entry — check [rbp-0x30]-ish) ===\n
info registers r14 r13d r12d
echo \n=== frame ===\n
printf "fr0 ret=%p\n", *(unsigned long long*)($rbp+8)
kill
quit
