set pagination off
set confirm off
set architecture i386:x86-64
target remote localhost:1234
break *0xffffffff9e642a90
continue
delete 1
printf "[+] btext\n"

break *0xffffffff9edf9177
commands
silent
printf "[READSITE] msgbufp=%p size=%#x\n", *(unsigned long long*)0xffffffffa1fb8a60, *(unsigned int*)0xffffffffa1d103e0
continue
end

break *0xffffffff9e8a0790
commands
silent
printf "[WRAPPER] rdi(buf)=%p esi(size)=%#x\n", $rdi, $esi
continue
end

break *0xffffffff9f025060
commands
silent
printf "[REINIT] rdi(mbp)=%p rsi(buf)=%p rdx(size)=%#x\n", $rdi, $rsi, $rdx
continue
end

break *0xffffffff9f02512f
commands
silent
printf "[FRESHINIT] rbx(mbp)=%p rsi(buf)=%p edx(size)=%#x\n", $rbx, $rsi, $edx
continue
end

break *0xffffffff9e8a07d7
commands
silent
printf "[FLAGSET] flag:=1 msgbufp=%p\n", *(unsigned long long*)0xffffffffa1fb8a60
continue
end

break *0xffffffff9ef7a475
printf "[+] AHCI-alloc crash hit - stopping\n"
info registers r13 rax rip
kill
quit
