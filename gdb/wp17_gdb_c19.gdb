target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e82bac4
c
echo \n=== BUCKET-TAIL TRYLOCK CALL ===\n
printf "zone (rbx) = %p\n", $rbx
printf "[zone+0x40] = %p   (lock container)\n", *(unsigned long long*)($rbx+0x40)
printf "rdi (the lock word) = %p\n", $rdi
echo \n=== the zone object ===\n
x/8gx $rbx
echo \n=== frame ===\n
printf "fr0 ret=%p\n", *(unsigned long long*)($rbp+8)
kill
quit
