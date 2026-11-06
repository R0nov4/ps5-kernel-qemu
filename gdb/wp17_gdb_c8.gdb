target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e946a00 if $rbx > 0 && $rbx < 0x1000
c
echo \n=== WALK THE TIMER'S CIRCULAR LIST ===\n
set $tm = *(unsigned long long*)($rbp-0xe8)
set $anc = *(unsigned long long*)($tm+8)
printf "timer=%p anchor=%p [anchor]=%p [anchor+8]=%p [anchor+0x10]=%p\n", $tm, $anc, *(unsigned long long*)($anc), *(unsigned long long*)($anc+8), *(unsigned long long*)($anc+0x10)
set $e = *(unsigned long long*)($anc)
set $i = 0
while ($e != 0 && $e != $anc && $i < 24)
  printf "elem[%d] = %p  next=[+8]=%p  prev=[+0x10]=%p  name=[+0x30]=%p\n", $i, $e, *(unsigned long long*)($e+8), *(unsigned long long*)($e+0x10), *(unsigned long long*)($e+0x30)
  set $e = *(unsigned long long*)($e+8)
  set $i = $i + 1
end
printf "walk ended at e=%p (i=%d)\n", $e, $i
echo \n=== the anchor memory ===\n
x/6gx $anc
kill
quit
