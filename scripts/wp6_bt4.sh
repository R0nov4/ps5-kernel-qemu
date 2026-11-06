#!/bin/bash
# WP6-BT4: watch the console/powerdown flow:
#  putchar, cnputc, debugcon-stub, powerdown-checker, powerdown-taken.
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64

cat > /tmp/wp6_bt4.gdb <<'EOF'
set pagination off
set confirm off
set height 0
target remote localhost:1234
break *0xffffffff9e89d890
break *0xffffffff9ef0d260
break *0xffffffff9e739bc0
break *0xffffffff9ebe0ce0
break *0xffffffff9ebe0d13
set $n = 0
while $n < 14
  continue
  printf "\n=== STOP #%d rip=%p ===\n", $n, $rip
  info registers rdi rsi rax rbx rcx rdx
  set $n = $n + 1
end
kill
EOF

rm -f wp3_boot/wp6_bt4.log
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 2G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/dev/null \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout 110 $GDB -batch -x /tmp/wp6_bt4.gdb > wp3_boot/wp6_bt4.log 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null
grep -a "STOP #\|rip=\|rdi\|rsi\|rax\|Breakpoint [0-9]" wp3_boot/wp6_bt4.log | head -60
