set pagination off
set confirm off
set architecture i386:x86-64
target remote localhost:1234
break *0xffffffff9e642a90
continue
delete 1

# the crashing allocator call: return addr 0x9ecd05e0 on stack
break *0xffffffff9ef7a1a0 if *(unsigned long long*)$rsp == 0xffffffff9ecd05e0
continue
delete 2
printf "\n=== CRASHING allocator call ENTRY ===\n"
info registers rdi rsi rdx

# zone alloc entry
break *0xffffffff9ea05730
continue
delete 3
printf "\n=== zone alloc ENTRY: domain=%d flag=%d arg3=%d ===\n", $rdi, $rsi, $rdx
set $zrdi = $rdi
set $zrsi = $rsi
set $zrdx = $rdx

# single-step trace, log until return to 0x9ef7a...
set $count = 0
set $log = ""
while $count < 420
  set $rip_v = $rip
  # stop when we return past the zone fn (ret to 0x9ef7a...)
  if ($rip_v >= 0xffffffff9ef7a400) && ($rip_v <= 0xffffffff9ef7a500)
    printf "\n=== returned to allocator at %p after %d steps ===\n", $rip_v, $count
    info registers rax
    break
  end
  printf "%04d %p rax=%016llx rbx=%016llx rcx=%016llx rdx=%016llx rsi=%016llx rdi=%016llx r13=%016llx r14=%016llx r15=%016llx\n", $count, $rip_v, $rax, $rbx, $rcx, $rdx, $rsi, $rdi, $r13, $r14, $r15
  stepi
  set $count = $count + 1
end
kill
quit
