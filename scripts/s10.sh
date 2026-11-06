#!/bin/bash
# WP5d phase 1: dump the full IVT (phys 0x0..0x400) at btext via identity map,
# locate the exact qword 0xc0007240f000ff53.
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64

cat > /tmp/ivt4.gdb <<'EOF'
set pagination off
set confirm off
target remote localhost:1234
hbreak *0xffffffff9e642a90
continue
printf "\n=== IVT full dump (VA 0x0..0x400 identity) ===\n"
x/128gx 0x0
printf "\n=== BDA 0x400..0x500 ===\n"
x/32gx 0x400
kill
EOF

rm -f wp3_boot/gdb_ivt4.txt
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 1G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/dev/null \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout 200 $GDB -batch -x /tmp/ivt4.gdb > wp3_boot/gdb_ivt4.txt 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null
grep -n "c0007240\|f000ff53" wp3_boot/gdb_ivt4.txt | head; echo "===== full IVT ====="; grep -A130 "IVT full dump" wp3_boot/gdb_ivt4.txt | head -135
