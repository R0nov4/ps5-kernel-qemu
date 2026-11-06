set pagination off
set confirm off
target remote :1234
break *0x0
continue

printf "\n===== NULL CALL caught =====\n"
info registers rax rbx rcx rdx rsi rdi rbp rsp rip

printf "\n--- return address (the caller!) ---\n"
x/gx $rsp

printf "\n--- stack window ---\n"
x/32gx $rsp

printf "\n--- caller context ---\n"
set $ret = *(unsigned long*)$rsp
x/10i $ret - 32

detach
quit
