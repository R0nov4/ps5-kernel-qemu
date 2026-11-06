set pagination off
set confirm off
set architecture i386:x86-64
target remote localhost:1234
break *0xffffffff9e926331
break *0xffffffff9e96b1cf
break *0xffffffff9ef7a475
set $n = 0
set $m = 0
set $done = 0
while $done == 0
  continue
  if $pc == 0xffffffff9ef7a475
    set $done = 1
  else
    if $pc == 0xffffffff9e926331
      set $n = $n + 1
      printf "SYSINIT[%d] slot=%#lx struct=%#lx sub=%d order=%d func=%#lx udata=%#lx\n", $n, $r12, $rax, *(int *)$rax, *(int *)($rax + 4), $rcx, *(unsigned long *)($rax + 0x10)
    else
      set $m = $m + 1
      printf "  METHOD[%d] node=%#lx thunk=%#lx\n", $m, $r12, $r14
    end
  end
end
echo \n=== CRASH STATE at 0x9ef7a475 ===\n
info registers rax rbx rcx rdx rsi rdi r13 r14 r15
echo \n=== being_run / end ===\n
x/gx 0xffffffffa19781b0
x/gx 0xffffffffa19781a8
echo \n=== TOTALS: stages executed before crash ===\n
printf "stages=%d methods=%d\n", $n, $m
detach
quit
