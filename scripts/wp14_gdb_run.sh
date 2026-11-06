#!/bin/bash
# WP14 GDB forensics: catch sleepq_add entry, dump args + caller chain + curthread
cd ./kit_build
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
GDB=./qemu-local/root/usr/bin/gdb

rm -f /tmp/w14_serial.log
$QEMU -L ./bios -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/tmp/w14_serial.log \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -gdb tcp::1234 -S -no-reboot 2>/dev/null &
QPID=$!
sleep 2

$GDB -q -batch -x ./scripts/wp14_gdb_w1.gdb 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null
echo "=== serial lines so far: $(wc -l < /tmp/w14_serial.log 2>/dev/null) ==="
