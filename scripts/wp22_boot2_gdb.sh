#!/bin/bash
# WP22 BOOT #2 — GDB combined diagnosis + live-heal experiment (LAST boot of budget)
cd ./wp22_kit
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
GDB=./qemu-local/root/usr/bin/gdb
rm -f serial.log gdb_out.txt
$QEMU -L ./bios -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=serial.log \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -gdb tcp::1234 -no-reboot 2>/dev/null &
QPID=$!

# attach at the kernel banner (early, long mode active, DMAP up)
for i in $(seq 1 90); do
  grep -a -q "SIE CONFIDENTIAL" serial.log 2>/dev/null && break
  kill -0 $QPID 2>/dev/null || break
  sleep 1
done
echo "attached after ${i}s (banner present: $(grep -a -c 'SIE CONFIDENTIAL' serial.log 2>/dev/null))"

timeout 200 $GDB -q -batch -x ./scripts/wp22_gdb_probe.gdb > gdb_out.txt 2>&1 || true
echo "gdb session ended; rc=$?"

# let the march continue and watch for landmark/crash
last=0; stall=0; hit=0
for i in $(seq 1 40); do
  sleep 20
  kill -0 $QPID 2>/dev/null || { echo "QEMU exited"; break; }
  grep -a -q "Power down" serial.log 2>/dev/null && { echo "panic tail"; break; }
  grep -a -q "Device configuration finished" serial.log 2>/dev/null && hit=1
  L=$(wc -l < serial.log 2>/dev/null || echo 0)
  if [ "$L" = "$last" ]; then stall=$((stall+1)); else stall=0; fi
  echo "t=$((i*20/60))m lines=$L stall=${stall} landmark=${hit}"
  last=$L
  [ $hit -eq 1 ] && [ $stall -ge 4 ] && { echo "(landmark + silence — the G26 park)"; break; }
  [ $hit -eq 0 ] && [ $stall -ge 9 ] && { echo "(3min silence — stall)"; break; }
done
kill $QPID 2>/dev/null; wait 2>/dev/null
echo "=== GDB OUTPUT ==="
cat gdb_out.txt
echo "=== serial tail ==="
tail -25 serial.log
