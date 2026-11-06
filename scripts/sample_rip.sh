#!/bin/bash
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 1G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=wp3_boot/serial.log \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout 100 $GDB -batch \
  -ex "set architecture i386:x86-64" \
  -ex "target remote localhost:1234" \
  -ex "break *0xffffffff9e642a90" \
  -ex "continue" \
  -ex "delete 1" \
  -ex "echo \n=== boot started; sampling RIP ===\n" \
  -ex "continue &" \
  2>&1 | head -5 &
sleep 25
# interrupt and sample several times
for i in 1 2 3 4 5; do
  echo "--- sample $i ---"
  timeout 10 $GDB -batch -ex "target remote localhost:1234" -ex "info registers rip rsp" -ex "x/4gx \$rsp" 2>/dev/null | grep -E "rip|rsp|0x" | head -4
  sleep 3
done
kill $QPID 2>/dev/null; wait 2>/dev/null
