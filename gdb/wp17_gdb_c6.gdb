target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

# WP17-C6: the eventtimer-list walker 0x9e9467c0 — dump the list state
b *0xffffffff9e9467c0 if $rdi >= 0xffff8e773f1a1000 && $rdi < 0xffff8e773f740000
c
echo \n=== WALKER ENTRY 0x9e9467c0 ===\n
printf "rdi (timer obj) = %p\n", $rdi
printf "[timer+8] (anchor) = %p\n", *(unsigned long long*)($rdi+8)
set $anc = *(unsigned long long*)($rdi+8)
printf "[anchor] (first elem) = %p\n", *(unsigned long long*)$anc
printf "[anchor+8] = %p  [anchor+0x10] = %p\n", *(unsigned long long*)($anc+8), *(unsigned long long*)($anc+0x10)
echo \n=== the timer object (first 0x40 bytes) ===\n
x/8gx $rdi
echo \n=== frame walk ===\n
printf "fr0: ret=%p\n", *(unsigned long long*)($rbp+8)
echo \n=== the caller's r14 ([rbp-0x30] of the caller) ===\n
set $fr1 = *(unsigned long long*)($rbp)
printf "caller rbp=%p ret=%p\n", $fr1, *(unsigned long long*)($fr1+8)
echo \n=== allocator state ===\n
printf "malloc-bump [0x3F1A0830]=%p  W1 [0x3F000000]=%p  ext [0x3F1A0840]=%p  pool [0x3F004008]=%p\n", \
  *(unsigned long long*)0xffff8e773f1a0830, *(unsigned long long*)0xffff8e773f000000, \
  *(unsigned long long*)0xffff8e773f1a0840, *(unsigned long long*)0xffff8e773f004008
shell tail -3 /tmp/w17_serial.log
kill
quit
