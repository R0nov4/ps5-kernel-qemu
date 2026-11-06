#!/bin/bash
# WP22 BOOT #1 — G28+G29 verification (patient, stall-detecting, bounded)
cd ./wp22_kit
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
rm -f serial.log
$QEMU -L ./bios -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=serial.log \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot 2>/dev/null &
QPID=$!
last=0; stall=0; hit=0
for i in $(seq 1 42); do
  sleep 20
  kill -0 $QPID 2>/dev/null || { echo "QEMU exited at $((i*20/60))m"; break; }
  grep -a -q "Power down" serial.log 2>/dev/null && { echo "panic tail at $((i*20/60))m"; break; }
  grep -a -q "Device configuration finished" serial.log 2>/dev/null && hit=1
  L=$(wc -l < serial.log 2>/dev/null || echo 0)
  if [ "$L" = "$last" ]; then stall=$((stall+1)); else stall=0; fi
  echo "t=$((i*20/60))m lines=$L stall=${stall} landmark=${hit}"
  last=$L
  [ $hit -eq 1 ] && [ $stall -ge 6 ] && { echo "(landmark + 2min silence — the G26 park)"; break; }
  [ $hit -eq 0 ] && [ $stall -ge 9 ] && { echo "(3min silence BEFORE the landmark — stall!)"; break; }
done
kill $QPID 2>/dev/null; wait 2>/dev/null
echo "=== last 30 lines of serial.log ==="
tail -30 serial.log
