target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

# break at the malloc call in the LAPIC eventtimer path
b *0xffffffff9e94719e
c
echo \n=== MALLOC ENTRY (LAPIC evtimer) ===\n
info registers rdi rsi rdx
printf "size=%ld flags=%#lx\n", $rdi, $rdx
echo \n=== step until ret or a interesting call ===\n
set $n = 0
while $n < 80
  ni
  set $n = $n + 1
  printf "%d: pc=%p rax=%p\n", $n, $pc, $rax
end
kill
quit
