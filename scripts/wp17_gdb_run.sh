#!/bin/bash
# WP17 GDB forensics runner — usage: wp16_gdb_run.sh <gdb_script> [serial_path]
cd ./kit_build
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
GDB=./qemu-local/root/usr/bin/gdb
SER=${2:-/tmp/w17_serial.log}

rm -f $SER
$QEMU -L ./bios -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=$SER \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -gdb tcp::1234 -S -no-reboot 2>/dev/null &
QPID=$!
sleep 2

timeout 300 $GDB -q -batch -x "$1" 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null
echo "=== serial lines so far: $(wc -l < $SER 2>/dev/null) ==="
tail -8 $SER 2>/dev/null
