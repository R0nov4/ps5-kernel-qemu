target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

# WP17-C2: trace the 0xF4000 large alloc through the kmem machinery
b *0xffffffff9e8f3dc3 if $rsi == 0xf4000
c
echo \n=== FILL->KMEM call site (size 0xF4000) ===\n
printf "rdi(map)=%p rsi(size)=%#lx rdx(flags)=%#x\n", $rdi, $rsi, $edx
printf "[0x9fed8b18] = %p\n", *(unsigned long long*)0xffffffff9fed8b18
printf "map+0x3e8(max)=%#lx  map+0x400(shift)=%#x\n", *(unsigned long long*)($rdi+0x3e8), *(unsigned char*)($rdi+0x400)
printf "map+0x428(thunk)=%p\n", *(unsigned long long*)($rdi+0x428)
si
echo \n=== KMEM ENTRY 0x9e9d6730 ===\n
printf "rdi=%p rsi=%#lx rdx=%#x rcx=%p\n", $rdi, $rsi, $rdx, $rcx
b *0xffffffff9e9d6794
b *0xffffffff9e9d674f
c
printf "\n=== BRANCH TAKEN: rip=%p ===\n", $rip
if $rip == 0xffffffff9e9d6794
  echo BUCKET PATH\n
  printf "map(rdi)=%p rcx(idx*5)=%#lx\n", $rdi, $rcx
  printf "bucket zone = %p\n", *(unsigned long long*)($rdi + $rcx*8 + 0x448)
  si
  echo \n=== BUCKET-ALLOC FN 0x9e82b880 ENTRY ===\n
  printf "rdi(bucketzone)=%p rsi=%#lx rdx=%#x\n", $rdi, $rsi, $rdx
  printf "[zone+0x68]=%p [zone+0x98]=%p [zone+0xb0]=%p [zone+0xb8]=%p\n", \
    *(unsigned long long*)($rdi+0x68), *(unsigned long long*)($rdi+0x98), \
    *(unsigned long long*)($rdi+0xb0), *(unsigned long long*)($rdi+0xb8)
else
  echo SLOW PATH (0x9e9d67c0)\n
end
b *0xffffffff9e82b760
c
echo \n=== DRAIN ENTRY (the crash fn) ===\n
printf "rdi(zone)=%p rsi(chunk)=%p\n", $rdi, $rsi
kill
quit
