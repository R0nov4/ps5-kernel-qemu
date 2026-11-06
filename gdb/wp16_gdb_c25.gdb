target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e9d7040
c
echo \n=== ARENA WAIT-FAIL STATE ===\n
echo "=== the arena object (r13 = 0xa1ab6f00) ===\n"
x/16gx $r13
echo "=== WP14 cave22 scratch: init+pool-next @0x3F004000 ===\n"
x/4gx 0xffff8e773f004000
echo "=== the arena extend thunk [r13+0x428] ===\n"
printf "[r13+0x428] = %p\n", *(unsigned long long *)($r13 + 0x428)
echo "=== serial ===\n"
shell tail -3 /tmp/w16_serial.log
kill
quit
