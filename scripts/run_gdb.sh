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
timeout 90 $GDB -batch \
  -ex "set architecture i386:x86-64" \
  -ex "target remote localhost:1234" \
  -ex "break *$1" \
  -ex "continue" \
  -ex "echo \n=== HIT ===\n" \
  -ex "info registers rdi rsi rdx rip rsp" \
  -ex "x/16gx \$rsp" \
  2>&1 | grep -vE "^\[|warning|Download|Reading"
kill $QPID 2>/dev/null; wait $QPID 2>/dev/null
