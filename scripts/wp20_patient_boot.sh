#!/bin/bash
# wp20_patient_boot.sh — boot with LONG patience (the vm_page scan SYSINITs
# take minutes under QEMU TCG). Polls serial.log for growth every 20s.
# usage: wp20_patient_boot.sh [minutes] [serial_path]
cd ./kit_build
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
MINS=${1:-12}
SER=${2:-serial.log}

rm -f $SER
$QEMU -L ./bios -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=$SER \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot 2>/dev/null &
QPID=$!
echo "QPID=$QPID  patience=${MINS}m"

last=0; stall=0
for i in $(seq 1 $((MINS*3))); do
  sleep 20
  kill -0 $QPID 2>/dev/null || { echo "QEMU exited at $((i*20/60))m$((i*20%60))s"; break; }
  L=$(wc -l < $SER 2>/dev/null || echo 0)
  if [ "$L" = "$last" ]; then stall=$((stall+1)); else stall=0; fi
  echo "t=$((i*20/60))m$((i*20%60))s lines=$L stall=${stall}"
  last=$L
  # stop after 3 minutes of total silence (kernel alive-quiet)
  [ $stall -ge 9 ] && { echo "(3min silence — kernel idle/quiet)"; break; }
done
kill $QPID 2>/dev/null; wait 2>/dev/null
echo "=== tail ==="
tail -15 $SER
