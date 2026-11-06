set pagination off
set confirm off
set architecture i386:x86-64
set remotetimeout 600
target remote localhost:1234
break *0xffffffff9e642a90
break *0xffffffff9e64d410
continue
printf "btext\n"
continue
continue
continue
printf "at msg3 (Found table): rdi=%p\n", $rdi
printf "caller of printf = %p\n", *(unsigned long long*)$rsp
finish
printf "printf returned; now at %p\n", $rip
set $n = 0
while $n < 400
  stepi
  if $n % 40 == 0
    printf "step %d: rip=%p\n", $n, $rip
  end
  set $n = $n + 1
end
printf "final rip=%p\n", $rip
kill
quit
