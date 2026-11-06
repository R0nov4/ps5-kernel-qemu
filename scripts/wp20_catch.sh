#!/bin/bash
# wp20_catch.sh — freeze-boot (-S), conditional breakpoint, dump chain.
# usage: wp20_catch.sh <gdb_script> [out_serial]
cd ./kit_build
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
GDB=./qemu-local/root/usr/bin/gdb
GS=$1
SER=${2:-/tmp/w20_catch_serial.log}

rm -f $SER
$QEMU -L ./bios -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=$SER \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -gdb tcp::1234 -S -no-reboot 2>/dev/null &
QPID=$!
sleep 3
timeout 420 $GDB -q -batch -x "$GS" 2>&1 | grep -vE "^warning|determining" | head -24
kill $QPID 2>/dev/null; wait 2>/dev/null
pkill -9 -f qemu-system 2>/dev/null
echo "=== serial tail ==="
tail -3 $SER 2>/dev/null
