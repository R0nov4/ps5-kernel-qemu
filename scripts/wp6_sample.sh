#!/bin/bash
# WP6-SAMPLE: boot WITHOUT gdb; sample RIP/progress via QEMU monitor socket.
# Usage: bash wp3_boot/wp6_sample.sh [total_sec=90] [step_sec=15]
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
T=${1:-90}
ST=${2:-15}

rm -f /tmp/wp6mon.sock wp3_boot/serial6.log
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 2G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null \
  -monitor unix:/tmp/wp6mon.sock,server,nowait \
  -chardev file,id=dbg,path=wp3_boot/serial6.log \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot 2>/dev/null &
QPID=$!
sleep 2
timeout $((T + 30)) python3 scripts/wp6_sample.py $T $ST
kill $QPID 2>/dev/null; wait 2>/dev/null
echo "=== serial6.log from PS5-TRAMPOLINE ==="
L=$(grep -an "PS5-TRAMPOLINE" wp3_boot/serial6.log 2>/dev/null | head -1 | cut -d: -f1)
tail -n +${L:-1} wp3_boot/serial6.log 2>/dev/null | head -30
