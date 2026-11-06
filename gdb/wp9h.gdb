set pagination off
set confirm off
set architecture i386:x86-64
set remotetimeout 600
target remote localhost:1234
break *0xffffffff9e642a90
break *0xffffffff9ee30270
continue
continue
set $v = *(unsigned long long*)0xffff8e77000ac000
printf "BEFORE: v=%p rax=%p rcx=%p\n", $v, $rax, $rcx
set *(unsigned long long*)0xffff8e77000ac000 = 0x1122334455667788
set $w = *(unsigned long long*)0xffff8e77000ac000
printf "GDB-WRITE: w=%p\n", $w
stepi
set $u = *(unsigned long long*)0xffff8e77000ac000
printf "CPU-STORE: u=%p rax=%p rcx=%p\n", $u, $rax, $rcx
kill
quit
