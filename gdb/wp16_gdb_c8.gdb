target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

# catch the W1 exhaustion (fires exactly once), inspect the lock + step to crash
b *0xffffffff9ee3013e
c

echo \n=== W1 EXHAUSTION ===\n
printf "bump (rcx) = %#lx\n", $rcx
printf "lock 0xa2170498 word [+0x18] = %#lx  (4 = FREE, thread-ptr = HELD)\n", *(unsigned long long *)0xffffffffa21704b0
printf "lock object dump:\n"
x/6gx 0xffffffffa2170498
echo \n=== step through the crash path ===\n
# return from the cave (ret), then walk to the write
ni
ni
ni
printf "pc now: %p\n", $pc
info registers rax r13 r14 rbx
echo \n=== keep stepping until 0x9ef7a475 ===\n
while $pc != 0xffffffff9ef7a475
  ni
end
printf "AT THE CRASH WRITE: r13 = %p\n", $r13
printf "lock word NOW = %#lx\n", *(unsigned long long *)0xffffffffa21704b0
echo \n=== serial ===\n
shell tail -2 /tmp/w16_serial.log
kill
quit
