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
sleep 20
echo "=== RSDP search in guest memory ==="
timeout 20 ./qemu-local/root/usr/bin/gdb -batch \
  -ex "target remote localhost:1234" \
  -ex "x/s 0x000e0000" \
  -ex "find /b 0xe0000, 0x100000, 0x52, 0x53, 0x44, 0x20, 0x50, 0x54, 0x52, 0x20" \
  -ex "x/2gx 0x40e" \
  -ex "find /b 0x9f000, 0xa0000, 0x52, 0x53, 0x44, 0x20, 0x50, 0x54, 0x52, 0x20" \
  2>/dev/null | grep -vE "^\[" | head -12
kill $QPID 2>/dev/null; wait 2>/dev/null
