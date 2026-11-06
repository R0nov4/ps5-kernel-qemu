target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e946a00 if $rbx > 0 && $rbx < 0x1000
c
echo \n=== PHASE-2 CRASH: rbx (element) ===\n
info registers rbx rbp r14 r15 r13 rax
echo \n=== the walker arg (timer): [rbp-0xe8] ===\n
set $tm = *(unsigned long long*)($rbp-0xe8)
printf "timer = %p  [timer+8] = %p  [timer+0x30] = %p\n", $tm, *(unsigned long long*)($tm+8), *(unsigned long long*)($tm+0x30)
echo \n=== the static anchor 0xa197a5a0 ===\n
x/6gx 0xffffffffa197a5a0
echo \n=== the timer object ===\n
x/8gx $tm
echo \n=== frame ===\n
printf "fr0 ret=%p\n", *(unsigned long long*)($rbp+8)
echo \n=== walk the circular list from the anchor ===\n
set $e = *(unsigned long long*)(0xffffffffa197a5a0+8)
printf "anchor.next(first?) = %p\n", $e
kill
quit
