target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e9471ad
c

echo \n=== MALLOC NULL — arena state ===\n
echo "=== WP14 cave22 scratch @0x3F004000 (init flag + pool next) ===\n"
x/8gx 0xffff8e773f004000
echo "=== arena pool region probe [0x3F200000..] ===\n"
x/4gx 0xffff8e773f200000
echo "=== the malloc type string (rsi at call was 0x9fec5bb0) ===\n"
x/s 0xffffffff9fec5bb0
echo "=== serial ===\n"
shell tail -2 /tmp/w16_serial.log
kill
quit
