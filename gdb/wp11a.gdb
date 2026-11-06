set pagination off
set confirm off
set $MAXFRAME = 12

target remote :1234
break *0xffffffff9e8b6c71
continue

printf "\n========== HIT breakpoint at 0x9e8b6c71 ==========\n"
info registers rax rbx rcx rdx rsi rdi rbp rsp r12 r13 r14 r15 rip

printf "\n--- lock word [r13] ---\n"
x/gx $r13
printf "\n--- mtx struct @ r13-0x18 (name@+0, flags@+8, recurse@+0xC, lock@+0x18) ---\n"
x/4gx $r13-0x18
printf "\n--- mutex name string ---\n"
x/s *(char**)($r13-0x18)

printf "\n--- thread r12 head ---\n"
x/4gx $r12
printf "--- r12+0x100..0x118 (stats/flags) ---\n"
x/4gx $r12+0x100

printf "\n--- stack window (rsp .. +0x240) ---\n"
x/72gx $rsp

printf "\n--- rbp chain walk ---\n"
set $f = $rbp
set $i = 0
while $i < $MAXFRAME
  printf "frame %d: rbp=%p retaddr=%p\n", $i, $f, *(unsigned long*)($f+8)
  set $f = *(unsigned long*)$f
  if $f == 0
    loop_break
  end
  set $i = $i + 1
end

printf "\n--- around return address [1] ---\n"
x/6i *(unsigned long*)($rbp+8) - 24

printf "\n--- around return address [2] ---\n"
set $f2 = *(unsigned long*)$rbp
x/6i *(unsigned long*)($f2+8) - 24

detach
quit
