#!/bin/bash
# WP21 GDB probe runner — boot WITHOUT -S, wait for the frontier landmark
# ('Device configuration finished.' — the G26 park), settle, attach GDB,
# read the done counter + the WP22 march head, detach, kill.
# usage: wp21_gdb_run.sh [wait_pattern] [serial_path] [settle_secs]
cd ./wp21_kit
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
GDB=./qemu-local/root/usr/bin/gdb
SER=${2:-/tmp/wp21_done_serial.log}
PAT=${1:-Device configuration finished}
SETTLE=${3:-10}

rm -f $SER
$QEMU -L ./bios -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=$SER \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -gdb tcp::1234 -no-reboot 2>/dev/null &
QPID=$!

# wait for the frontier landmark (max 22 min — the TCG march is slow)
for i in $(seq 1 1320); do
  grep -a -q "$PAT" $SER 2>/dev/null && break
  kill -0 $QPID 2>/dev/null || break
  sleep 1
done
sleep $SETTLE
echo "=== serial tail at attach time ==="
tail -3 $SER
echo "=== attaching GDB ==="
timeout 90 $GDB -q -batch -x ./wp21_kit/scripts/wp21_gdb_probe.gdb 2>/dev/null
kill $QPID 2>/dev/null; wait 2>/dev/null
