target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

set $base = 0xffffffffa1ab6f00
set $tdlocks = (short*)0xffffffffa197896a

b *0xffffffff9e8b6a00 if $rdi >= $base && $rdi < $base + 0x40
commands
silent
printf "LOCK   %p  caller=%p  td_locks=%d\n", $rdi, *(unsigned long long*)$rsp, *$tdlocks
continue
end
b *0xffffffff9e8b6fa0 if $rdi >= $base && $rdi < $base + 0x40
commands
silent
printf "UNLOCK %p  caller=%p  td_locks=%d\n", $rdi, *(unsigned long long*)$rsp, *$tdlocks
continue
end
b *0xffffffff9e9d68d1
commands
silent
printf "  [site] entry-lock 0x9e9d68d1  td_locks=%d\n", *$tdlocks
continue
end
b *0xffffffff9e9d6ad0
commands
silent
printf "  [site] pre-extend UNLOCK 0x9e9d6ad0  td_locks=%d\n", *$tdlocks
continue
end
b *0xffffffff9e9d6b09
commands
silent
printf "  [site] THUNK CALL r8=%p rsi=%#lx  td_locks=%d\n", $r8, $rsi, *$tdlocks
continue
end
b *0xffffffff9e9d6b19
commands
silent
printf "  [site] post-extend RE-LOCK 0x9e9d6b19  td_locks=%d\n", *$tdlocks
continue
end
b *0xffffffff9e9d6c26
commands
silent
printf "  [site] wait-block head 0x9e9d6c26  td_locks=%d\n", *$tdlocks
continue
end
b *0xffffffff9e9d7066
commands
silent
printf "  [site] NOWAIT-fail return 0x9e9d7066  td_locks=%d\n", *$tdlocks
continue
end
b *0xffffffff9e9d6ffc
commands
silent
printf "  [site] TAIL UNLOCK 0x9e9d6ffc  td_locks=%d\n", *$tdlocks
continue
end

b *0xffffffff9e8b70b9
c
echo \n=== PANIC SITE REACHED ===\n
info registers r12 r14 rbp rsp
printf "td_locks = %d\n", *$tdlocks
kill
quit
