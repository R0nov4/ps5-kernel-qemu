set pagination off
set confirm off
set architecture i386:x86-64
target remote localhost:1234
break *0xffffffff9e642a90
continue
delete 1

# catch the allocator entry (the crashing call comes from 0x9ecd05db's fn)
break *0xffffffff9ef7a1a0
continue
delete 2
printf "\n=== allocator 0x9ef7a1a0 ENTRY ===\n"
info registers rdi rsi rdx
printf "arg1(container)=%p arg2=%p arg3(size/class)=%p\n", $rdi, $rsi, $rdx

# step to the zone alloc call
break *0xffffffff9ea05730
continue
delete 3
printf "\n=== zone alloc 0x9ea05730 ENTRY ===\n"
info registers rdi rsi rdx
printf "domain=%d flag=%d arg3=%d\n", $rdi, $rsi, $rdx

# catch return of zone alloc: breakpoint after the call site
break *0xffffffff9ef7a421
continue
delete 4
printf "\n=== after first zone-alloc call ===\n"
info registers rax rbx rcx rdx rsi rdi r12 r13 r14 r15
printf "result rax = %p\n", $rax

# table state NOW
printf "\n=== carve table entry math ===\n"
printf "count [0xa1add944]=%d\n", *(int*)0xffffffffa1add944
x/16gx 0xffffffffa1add9a0
printf "=== zone lock area 0xa1cf2f90 ===\n"
x/8gx 0xffffffffa1cf2f90

# step into the retry / failure
break *0xffffffff9ef7a428
continue
delete 5
printf "\n=== can-wait check 0x9e945d80 ===\n"
info registers rax rdi
break *0xffffffff9ef7a42d
continue
delete 6
printf "wait-check result eax=%d\n", $rax

# second zone alloc result
break *0xffffffff9ef7a441
continue
delete 7
printf "\n=== after RETRY zone-alloc ===\n"
info registers rax rbx r12 r13 r14 r15
printf "retry result rax = %p  (r13 will take this)\n", $rax

# final crash site
break *0xffffffff9ef7a475
continue
delete 8
printf "\n=== CRASH 0x9ef7a475: r13=%p rax=%p r14d=%d\n", $r13, $rax, $r14
kill
quit
