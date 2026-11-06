#!/bin/bash
# WP11 — boot with GDB stub, frozen at start (-S), run a GDB batch, kill.
# usage: bash wp11_boot_gdb.sh <gdb-script> [timeout_sec]
GDBSCRIPT=$1
TMO=${2:-420}
cd ./kit_build
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu

rm -f serial_gdb.log
$QEMU -L ./bios \
  -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=serial_gdb.log \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -S -s -no-reboot 2>/dev/null &
QPID=$!
sleep 1

LD_LIBRARY_PATH=./scripts/gdbx/usr/lib/x86_64-linux-gnu \
  timeout $TMO ./scripts/gdbx/usr/bin/gdb \
    -batch -q -x "$GDBSCRIPT" 2>&1

kill $QPID 2>/dev/null; wait 2>/dev/null
echo "=== serial_gdb.log tail ==="
tail -4 serial_gdb.log 2>/dev/null
