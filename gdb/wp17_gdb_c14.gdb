target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e82b933 if $rax > 0 && $rax < 0x1000000
c
echo \n=== CRASH STATE + the malloc frame locals ===\n
set $baf = $rbp
set $mf = *(unsigned long long*)($baf)
printf "bucket-alloc rbp=%p  malloc rbp=%p\n", $baf, $mf
printf "malloc [rbp-0x40] (r15=ctx saved?) = %p\n", *(unsigned long long*)($mf-0x40)
printf "malloc [rbp-0x30] = %p  [rbp-0x38] = %p\n", *(unsigned long long*)($mf-0x30), *(unsigned long long*)($mf-0x38)
set $ctx = *(unsigned long long*)($mf-0x40)
echo \n=== the ctx object ===\n
x/6gx $ctx
printf "[ctx+0x18] (the zone table) = %p\n", *(unsigned long long*)($ctx+0x18)
set $zt = *(unsigned long long*)($ctx+0x18)
x/4gx $zt
echo \n=== the bucket slot's zone (rbx) ===\n
printf "zone=%p  r14 (slot)=%p\n", $rbx, $r14
kill
quit
