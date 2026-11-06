#!/bin/bash
# WP20 GDB probe runner — boot WITHOUT -S, wait for a serial pattern (or
# quiet), attach GDB, run the probe script (sysinit done-count + walk chain).
# usage: wp20_gdb_run.sh [wait_pattern] [serial_path] [settle_secs]
cd ./kit_build
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
GDB=./qemu-local/root/usr/bin/gdb
SER=${2:-/tmp/w20_serial.log}
PAT=${1:-module_register_init}
SETTLE=${3:-6}

rm -f $SER
$QEMU -L ./bios -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=$SER \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -gdb tcp::1234 -no-reboot 2>/dev/null &
QPID=$!

# wait for the frontier line (max 150s), then settle
for i in $(seq 1 720); do
  grep -a -q "$PAT" $SER 2>/dev/null && break
  kill -0 $QPID 2>/dev/null || break
  sleep 1
done
sleep $SETTLE
echo "=== serial tail at attach time ==="
tail -3 $SER
echo "=== attaching GDB ==="
timeout 60 $GDB -q -batch -x ./scripts/wp20_gdb_probe.gdb 2>/dev/null
kill $QPID 2>/dev/null; wait 2>/dev/null
