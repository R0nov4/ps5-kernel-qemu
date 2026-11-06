set pagination off
set confirm off
target remote :1234
break *0xffffffff9e8b6c71
continue

printf "\n===== W1 bump allocator state =====\n"
printf "bump counter @DMAP(0x3F000000): "
x/gx 0xffff8e773f000000
printf "list-tail    @DMAP(0x3F000008): "
x/gx 0xffff8e773f000008
printf "bitmap       @DMAP(0x3F001000):\n"
x/8gx 0xffff8e773f001000

printf "\n===== first W1 objects (0x3F010000..) =====\n"
x/8gx 0xffff8e773f010000

printf "\n===== zone74 @ 0x3F0122B0 (mtx @ +0x30, lock @ +0x48) =====\n"
x/12gx 0xffff8e773f0122b0

printf "\n===== zone74 name candidates =====\n"
printf "uz_name-ish [+0x18] [+0x20]:\n"
x/2gx 0xffff8e773f0122c8

printf "\n===== mi_startup frame (rbp=0xffffffffa2228a30) locals =====\n"
x/16gx 0xffffffffa22289c0

printf "\n===== caller stage fn region 0x9e926333 =====\n"
x/8i 0xffffffff9e926300

printf "\n===== callers 0x9ebd7b57 / 0x9ef783f7 context =====\n"
x/6i 0xffffffff9ebd7b40
x/6i 0xffffffff9ef783e0

printf "\n===== sysinit mode global [0x9fcd446c] =====\n"
x/gx 0xffffffff9fcd446c

printf "\n===== zone r14 in caller: dump stack slots around frame0 =====\n"
x/4gx $rsp+0x28

detach
quit
