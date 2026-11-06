set pagination off
set confirm off
set architecture i386:x86-64
target remote localhost:1234
break *0xffffffff9e642a90
continue
delete 1

# break at the crash site directly (the crashing allocator call)
break *0xffffffff9ef7a475
continue
delete 2
printf "\n=== CRASH 0x9ef7a475 regs ===\n"
info registers rax rbx rcx rdx rsi rdi r12 r13 r14 r15

printf "\n=== full carve table region dump (0xa1add9a0 + 0x600) ===\n"
x/192gx 0xffffffffa1add9a0

printf "\n=== region descriptors @0xa1adde30 / 0xa1addc20 ===\n"
x/16gx 0xffffffffa1adde30
x/16gx 0xffffffffa1addc20

printf "\n=== zone/budget struct passed (stack locals of 0x9ea05730) ===\n"
x/12gx $rsp

printf "\n=== stack around rbp for caller args ===\n"
printf "rbp=%p\n", $rbp
x/32gx $rbp-0x80

printf "\n=== physfree area: check 0x222de000 region via DMAP ===\n"
x/4gx 0xffff8e77222de000
x/4gx 0xffff8e7730000000
kill
quit
