#!/bin/bash
# wp20_fastboot.sh — boot, kill on 'Power down' (the panic tail) or N sec silence.
# usage: wp20_fastboot.sh [max_seconds]
cd ./kit_build
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
MAX=${1:-150}

rm -f serial.log
$QEMU -L ./bios -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=serial.log \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot 2>/dev/null &
QPID=$!

last=0; quiet=0
for i in $(seq 1 $MAX); do
  sleep 1
  kill -0 $QPID 2>/dev/null || break
  grep -a -q "Power down" serial.log 2>/dev/null && { sleep 1; break; }
  L=$(wc -c < serial.log 2>/dev/null || echo 0)
  if [ "$L" = "$last" ]; then quiet=$((quiet+1)); else quiet=0; last=$L; fi
  [ $quiet -ge 60 ] && [ "$L" -gt 200 ] && break
done
kill $QPID 2>/dev/null; wait 2>/dev/null
pkill -9 -f qemu-system 2>/dev/null
echo "=== lines: $(wc -l < serial.log) ==="
grep -a "instruction pointer" serial.log | tail -1
sed -n '/Fatal trap/,/fault code/p' serial.log | grep "fault virtual"
tail -4 serial.log
