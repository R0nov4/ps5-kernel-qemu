set pagination off
set confirm off
target remote :1234
break *0xffffffff9e82da83
continue
printf "AT CALL SITE — stepping into the tree\n"
set $i = 0
while $i < 3000
  si
  printf "s%d rip=%p\n", $i, $rip
  if $rip == 0
    printf "=== NULL REACHED at step %d ===\n", $i
    loop_break
  end
  set $i = $i + 1
end
info registers rax rbx rcx rdx rsi rdi rip rsp
x/4gx $rsp
detach
quit
