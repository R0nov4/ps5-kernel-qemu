#!/bin/bash
# WP19 GDB phase-1 runner — boot WITHOUT -S, wait for gc_suspend_resume line,
# then attach GDB (QEMU freezes on connect) and run the analysis script.
# usage: wp19_gdb_run.sh <gdb_script> [serial_path] [wait_pattern]
cd ./kit_build
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
GDB=./qemu-local/root/usr/bin/gdb
SER=${2:-/tmp/w19_serial.log}
PAT=${3:-gc_suspend_resume}

rm -f $SER
$QEMU -L ./bios -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=$SER \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -gdb tcp::1234 -no-reboot 2>/dev/null &
QPID=$!

# wait for the frontier line (max 120s)
for i in $(seq 1 120); do
  grep -a -q "$PAT" $SER 2>/dev/null && break
  kill -0 $QPID 2>/dev/null || break
  sleep 1
done
sleep 4    # let it settle into the stall
echo "=== serial tail at attach time ==="
tail -4 $SER
echo "=== attaching GDB ==="
$GDB -q -batch -x "$1" 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null
echo "=== serial lines total: $(wc -l < $SER 2>/dev/null) ==="
