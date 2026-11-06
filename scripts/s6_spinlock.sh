#!/bin/bash
# WP3-4: GDB spin-lock timeout hunt — break at the panic site 0xffffffff9e8b79ac
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
GDB=./qemu-local/root/usr/bin/gdb

rm -f wp3_boot/gdb_spin.txt
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 1G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/dev/null \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1

timeout 240 $GDB -batch \
  -ex "set pagination off" \
  -ex "target remote localhost:1234" \
  -ex "break *0xffffffff9e8b79ac" \
  -ex "continue" \
  -ex "echo \n=== HIT SPIN-TIMEOUT PANIC SITE ===\n" \
  -ex "info registers rbx r12 r13 r14 rsi rdi rbp rsp rip" \
  -ex "echo \n=== LOCK STRUCT [rbx] ===\n" \
  -ex "x/8gx \$rbx" \
  -ex "echo \n=== STACK SCAN (return addresses) ===\n" \
  -ex "x/80gx \$rsp" \
  -ex "kill" \
  > wp3_boot/gdb_spin.txt 2>&1 &
GPID=$!

# wait for gdb to finish (max 240s)
wait $GPID 2>/dev/null
kill $QPID 2>/dev/null; wait 2>/dev/null
echo "=== gdb_spin.txt ==="
grep -E "HIT|rbx|r12|r13|r14|rsi|rdi|rbp|rsp|rip|0x[0-9a-f]+:" wp3_boot/gdb_spin.txt | head -120
