set pagination off
set confirm off
set architecture i386:x86-64
target remote localhost:1234
break *0xffffffff9e642a90
continue
printf "[+] at btext\n"
delete 1

# first-panic site (r13 NULL deref)
break *0xffffffff9ef7a475
printf "[+] armed panic site; continuing...\n"
continue

printf "\n=== FIRST-PANIC HIT @ rip=%p ===\n", $rip
info registers r13 r14 rax rbx rdi rsi rip
printf "r13 = %p  (object being freed, NULL)\n", $r13
bt 12
printf "\n=== stack words ===\n"
x/40gx $rsp

printf "\n=== MSGBUF DUMP (DMAP 0xf00000, 96KB) ===\n"
dump binary memory ./wp3_boot/wp7_msgbuf.bin 0xffff8e770f000000 0xffff8e770f018000
printf "[+] msgbuf saved\n"
printf "msgbuf magic: "
x/1wx 0xffff8e770f0017fb8+8
kill
quit
