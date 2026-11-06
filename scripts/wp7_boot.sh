#!/bin/bash
# WP7 boot test — patched kernel (msgbuf redirect + ICC defuse)
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64

TMO=${1:-240}
rm -f wp3_boot/serial.log

$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=wp3_boot/serial.log \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot 2>/dev/null &
QPID=$!

# watch serial.log grow; stop early if it goes quiet > 45s after having output
last_size=0
quiet=0
for i in $(seq 1 $TMO); do
  sleep 1
  kill -0 $QPID 2>/dev/null || break
  sz=$(stat -c%s wp3_boot/serial.log 2>/dev/null || echo 0)
  if [ "$sz" = "$last_size" ]; then
    quiet=$((quiet+1))
    if [ $quiet -ge 45 ] && [ "$sz" -gt 200 ]; then break; fi
  else
    quiet=0
    last_size=$sz
  fi
done
kill $QPID 2>/dev/null; wait 2>/dev/null

echo "=== serial.log size: $(stat -c%s wp3_boot/serial.log 2>/dev/null) bytes ==="
echo "=== first 25 lines ==="
head -25 wp3_boot/serial.log 2>/dev/null
echo "=== last 40 lines ==="
tail -40 wp3_boot/serial.log 2>/dev/null
