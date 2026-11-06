set pagination off
set confirm off
set architecture i386:x86-64
target remote localhost:1234
break *0xffffffff9e642a90
continue
delete 1
printf "\n=== btext reached ===\n"

# SYSINIT[2] dispatcher: catch right after list head load
break *0xffffffff9e96b178
continue
delete 2
printf "\n=== SYSINIT[2] 0x9e96b140 entered; runtime list walk ===\n"
set $n = *(unsigned long long*)0xffffffffa19d3b80
printf "list head = %p\n", $n
set $i = 0
while $n != 0 && $i < 24
  printf "node[%d] @ %p  thunk=%p  next=%p\n", $i, $n, *(unsigned long long*)($n+8), *(unsigned long long*)($n+0x28)
  set $n = *(unsigned long long*)($n+0x28)
  set $i = $i + 1
end
printf "bootverbose [0xa1978858] = %d\n", *(int*)0xffffffffa1978858
printf "being_run  [0xa19781b0] = %p\n", *(unsigned long long*)0xffffffffa19781b0

# carve allocator state BEFORE the crash
printf "\n=== carve table @0xa1add9a0 (runtime) ===\n"
x/16gx 0xffffffffa1add9a0
printf "count [0xa1add944] = %d\n", *(int*)0xffffffffa1add944
printf "=== profile[0] @0xa1925ea0 (runtime) ===\n"
x/8gx 0xffffffffa1925ea0
printf "=== window globals ===\n"
printf "[0xa1f39294]=%d [0xa1f39298]=%d\n", *(int*)0xffffffffa1f39294, *(int*)0xffffffffa1f39298
printf "[0xa1f39018]=%p [0xa1f38ff8]=%p\n", *(unsigned long long*)0xffffffffa1f39018, *(unsigned long long*)0xffffffffa1f38ff8

# now run to the crash
break *0xffffffff9ef7a475
continue
delete 3
printf "\n=== CRASH SITE 0x9ef7a475 hit ===\n"
info registers rax rbx rcx rdx rsi rdi rbp rsp r12 r13 r14 r15 rip
printf "\n=== stack (return addrs) ===\n"
x/24gx $rsp
printf "\n=== carve table @0xa1add9a0 at crash ===\n"
x/24gx 0xffffffffa1add9a0
printf "count [0xa1add944] = %d\n", *(int*)0xffffffffa1add944
printf "=== profile @0xa1925ea0 at crash ===\n"
x/8gx 0xffffffffa1925ea0
printf "=== zone globals ===\n"
x/4gx 0xffffffffa1cf2f90
printf "=== container arg (r12 of allocator) — walk frame ===\n"
set $frame = $rbp
printf "allocator rbp=%p  [rbp-0x50]=%p [rbp-0x58]=%p\n", $frame, *(unsigned long long*)($frame-0x50), *(unsigned long long*)($frame-0x58)
kill
quit
