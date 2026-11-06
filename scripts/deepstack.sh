#!/bin/bash
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 1G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/dev/null \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout 200 ./qemu-local/root/usr/bin/gdb -batch \
  -ex "target remote localhost:1234" \
  -ex "break *0xffffffff9e642a90" -ex "continue" -ex "delete" \
  >/dev/null 2>&1 &
sleep 40
timeout 20 ./qemu-local/root/usr/bin/gdb -batch \
  -ex "target remote localhost:1234" \
  -ex "set \$sp = \$rsp" \
  -ex "x/120gx \$rsp" \
  2>/dev/null | grep "0xffffffff9" | awk '{print $2}' | head -60 > /tmp/deepstack.txt
kill $QPID 2>/dev/null; wait 2>/dev/null
cat /tmp/deepstack.txt
