set pagination off
set confirm off
set architecture i386:x86-64
target remote localhost:1234
break *0xffffffff9e642a90
continue
delete 1
break *0xffffffff9ef7a475
continue
printf "=== AHCI crash hit; dumping msgbuf ===\n"
set $mbp = *(unsigned long long*)0xffffffffa1fb8a60
printf "msgbufp = %p\n", $mbp
printf "struct fields: "
x/9gx $mbp
printf "gate flag: "
x/1bx 0xffffffffa1926628
printf "conslog var [0xa192662c]: "
x/1wx 0xffffffffa192662c
set $buf = *(unsigned long long*)$mbp
printf "buf = %p\n", $buf
dump binary memory ./wp3_boot/wp7_msgbuf.bin $buf $buf + 0x18000
printf "[+] dumped 96KB from buf\n"
kill
quit
