#!/bin/bash
# WP9 focused allocator trace
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
SCRIPT=${1:-wp9b}
TMO=${2:-240}

$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=wp3_boot/serial.log \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout $TMO $GDB -batch -x wp3_boot/$SCRIPT.gdb 2>&1 | grep -vE "^\[|warning:|Download|Reading|missing"
kill $QPID 2>/dev/null; wait $QPID 2>/dev/null
echo "=== done ==="
