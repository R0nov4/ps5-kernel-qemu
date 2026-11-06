target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e94719e
c
echo \n=== STEP INTO MALLOC ===\n
set $n = 0
while $n < 60
  si
  set $n = $n + 1
  printf "%d: pc=%p rax=%p rbx=%p rcx=%p r14=%p\n", $n, $pc, $rax, $rbx, $rcx, $r14
end
kill
quit
