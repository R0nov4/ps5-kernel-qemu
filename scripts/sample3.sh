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
# start and run 60s
timeout 200 ./qemu-local/root/usr/bin/gdb -batch \
  -ex "target remote localhost:1234" \
  -ex "break *0xffffffff9e642a90" -ex "continue" -ex "delete" \
  >/dev/null 2>&1 &
sleep 60
echo "=== sample at t=60s ==="
timeout 15 ./qemu-local/root/usr/bin/gdb -batch \
  -ex "target remote localhost:1234" \
  -ex "info registers rip rbp r15 r12" \
  -ex "p/x *(unsigned long*)(\$rbp-0x40)" \
  -ex "p/x *(unsigned long*)(\$rbp-0x38)" \
  -ex "x/8gx \$rsp" 2>/dev/null | grep -E "rip|rbp|r15|r12|\\\$[0-9]|0xffffffff" | head -14
sleep 30
echo "=== sample at t=90s ==="
timeout 15 ./qemu-local/root/usr/bin/gdb -batch \
  -ex "target remote localhost:1234" \
  -ex "info registers rip rbp r15" \
  -ex "p/x *(unsigned long*)(\$rbp-0x40)" 2>/dev/null | grep -E "rip|rbp|r15|\\\$" | head -6
kill $QPID 2>/dev/null; wait 2>/dev/null
