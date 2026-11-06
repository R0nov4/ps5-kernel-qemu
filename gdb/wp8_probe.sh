#!/bin/bash
# WP8 crash probe — breakpoint at 0x9ef7a475 (AHCI allocator stamp write)
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64

rm -f wp3_boot/serial_probe.log
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=wp3_boot/serial_probe.log \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout 150 $GDB -batch -x ./scripts/wp8_probe.gdb 2>&1 | \
  grep -vE "^\[|warning|Download|Reading"
kill $QPID 2>/dev/null; wait $QPID 2>/dev/null
echo "=== probe serial tail ==="
tail -5 wp3_boot/serial_probe.log 2>/dev/null
echo "done"
