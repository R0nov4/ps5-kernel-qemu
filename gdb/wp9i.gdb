set pagination off
set confirm off
set architecture i386:x86-64
set remotetimeout 600
target remote localhost:1234
break *0xffffffff9e642a90
break *0xffffffff9ecdba10
continue
printf "btext reached\n"
set $n = 0
while $n < 4
  continue
  printf "map call %d: rdi(phys)=%p rsi=%p caller=%p\n", $n+1, $rdi, $rsi, *(unsigned long long*)$rsp
  set $n = $n + 1
end
kill
quit
