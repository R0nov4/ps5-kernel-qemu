target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

# break at the region-manager alloc (WP12-seeded zero page)
b *0xffffffff9e6bb1b0
c

echo \n=== REGION MGR ALLOC ENTRY ===\n
info registers rdi rsi rdx rcx r8 r9 rbp rsp
echo \n=== the manager object (rdi) ===\n
x/16gx $rdi
echo \n=== map object rbx = [rdi+0x428]-thunk? ===\n
printf "[rdi+0x428] = %p\n", *(unsigned long long *)($rdi + 0x428)
echo \n=== serial ===\n
shell tail -2 /tmp/w16_serial.log
kill
quit
