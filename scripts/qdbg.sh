#!/bin/bash
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64

rm -f wp3_boot/serial.log /tmp/qerr.txt
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=wp3_boot/serial.log \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot 2>/tmp/qerr.txt &
QPID=$!
sleep 15
echo "=== qemu alive? ==="
kill -0 $QPID 2>/dev/null && echo "ALIVE pid=$QPID" || echo "DEAD"
echo "=== stderr (unique lines) ==="
sort -u /tmp/qerr.txt | head -8
echo "=== serial.log size: $(stat -c%s wp3_boot/serial.log 2>/dev/null) ==="
head -20 wp3_boot/serial.log 2>/dev/null
kill $QPID 2>/dev/null; wait 2>/dev/null
echo "done"
