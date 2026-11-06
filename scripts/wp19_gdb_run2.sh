#!/bin/bash
# WP19 GDB crash-chase runner — boot, wait for pattern, attach, run script
cd ./kit_build
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
GDB=./qemu-local/root/usr/bin/gdb
SER=${2:-/tmp/w19_serial.log}
PAT=${3:-"APIC: CPU 0 has ACPI ID"}

rm -f $SER
$QEMU -L ./bios -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=$SER \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -gdb tcp::1234 -no-reboot 2>/dev/null &
QPID=$!
for i in $(seq 1 100); do
  grep -a -q "$PAT" $SER 2>/dev/null && break
  kill -0 $QPID 2>/dev/null || break
  sleep 1
done
sleep 1
echo "=== serial tail: $(tail -c 200 $SER | tr '\n' ' ') ==="
timeout 200 $GDB -q -batch -x "$1" 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null
echo "=== serial lines: $(wc -l < $SER 2>/dev/null) ==="
