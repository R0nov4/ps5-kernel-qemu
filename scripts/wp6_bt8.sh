#!/bin/bash
# WP6-BT8: GDB at the log-read crash (0x9f025066) to find the rdi source.
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64

cat > /tmp/wp6_bt8.gdb <<'EOF'
set pagination off
set confirm off
set height 0
target remote localhost:1234
hbreak *0xffffffff9f025066
continue
printf "=== AT LOG-READ CRASH ===\n"
info registers rdi rsi rdx rbx rax rcx r8
printf "struct @ rdi: "
x/8gx $rdi
printf "stack: "
x/8gx $rsp
kill
EOF

rm -f wp3_boot/wp6_bt8.log
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 2G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/dev/null \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout 100 $GDB -batch -x /tmp/wp6_bt8.gdb > wp3_boot/wp6_bt8.log 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null
grep -av "^warning" wp3_boot/wp6_bt8.log | tail -25
