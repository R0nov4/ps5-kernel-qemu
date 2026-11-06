#!/bin/bash
# wp21_patient_boot.sh — boot with LONG patience (the deep SYSINITs take
# minutes under QEMU TCG). Polls serial.log for growth every 20s; stops
# early when the designed frontier stop parks the CPU (long silence) or
# when the panic tail ('Power down') appears.
# usage: wp21_patient_boot.sh [minutes] [serial_path]
cd ./wp21_kit
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
MINS=${1:-14}
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

last=0; stall=0; hit=0
for i in $(seq 1 $((MINS*3))); do
  sleep 20
  kill -0 $QPID 2>/dev/null || { echo "QEMU exited at $((i*20/60))m$((i*20%60))s"; break; }
  grep -a -q "Power down" $SER 2>/dev/null && { echo "panic tail at $((i*20/60))m"; break; }
  if grep -a -q "Device configuration finished" $SER 2>/dev/null && [ $hit -eq 0 ]; then
    echo "=== FRONTIER LANDMARK at $((i*20/60))m$((i*20%60))s — parking detected ==="
    hit=1
  fi
  L=$(wc -l < $SER 2>/dev/null || echo 0)
  if [ "$L" = "$last" ]; then stall=$((stall+1)); else stall=0; fi
  echo "t=$((i*20/60))m$((i*20%60))s lines=$L stall=${stall} landmark=${hit}"
  last=$L
  # the designed stop = landmark printed + 2 minutes of total silence
  [ $hit -eq 1 ] && [ $stall -ge 6 ] && { echo "(landmark + 2min silence — the designed stop)"; break; }
  # no landmark: 3 minutes of total silence (kernel alive-quiet — a stall)
  [ $hit -eq 0 ] && [ $stall -ge 9 ] && { echo "(3min silence BEFORE the landmark — stall!)"; break; }
done
kill $QPID 2>/dev/null; wait 2>/dev/null
echo "=== tail ==="
tail -8 $SER
