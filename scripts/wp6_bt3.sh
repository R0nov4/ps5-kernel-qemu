#!/bin/bash
# WP6-BT3: which walker loop spins? Break at loop head + both advance paths.
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64

cat > /tmp/wp6_bt3.gdb <<'EOF'
set pagination off
set confirm off
set height 0
target remote localhost:1234
break *0xffffffff9ead22b0
break *0xffffffff9ead2406
break *0xffffffff9ead23f0
break *0xffffffff9ead224c
break *0xffffffff9ead2287
set $n = 0
while $n < 10
  continue
  printf "\n=== STOP #%d rip=%p ===\n", $n, $rip
  info registers rax rbx rcx rdx rsi rdi r13 r14 r15 rbp
  printf "r15 points to: "
  x/s $r15
  set $n = $n + 1
end
kill
EOF

rm -f wp3_boot/wp6_bt3.log
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 2G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/dev/null \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout 100 $GDB -batch -x /tmp/wp6_bt3.gdb > wp3_boot/wp6_bt3.log 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null
grep -a "STOP #\|rip=\|r15\|points\|0xffffffff9ead\|Breakpoint" wp3_boot/wp6_bt3.log | head -70
