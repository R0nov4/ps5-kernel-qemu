#!/bin/bash
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
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
timeout 200 ./qemu-local/root/usr/bin/gdb -batch \
  -ex "target remote localhost:1234" \
  -ex "break *0xffffffff9e642a90" -ex "continue" -ex "delete" \
  -ex "break *0xffffffff9e739bc0" \
  -ex "continue" \
  -ex "x/12i \$rip" \
  -ex "x/12xb \$rip" \
  -ex "set \$sil = 0x41" \
  -ex "stepi 3" \
  -ex "info registers rip rax rdx" \
  2>/dev/null | grep -vE "^\[|warning" | head -22
kill $QPID 2>/dev/null; wait 2>/dev/null
