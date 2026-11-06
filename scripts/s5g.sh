#!/bin/bash
# WP4: GDB sampling hunt — where is the silent kernel stuck?
# Boots with -S -gdb, continues at btext, then samples RIP twice.
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
WAIT1=${1:-45}    # seconds before first sample
WAIT2=${2:-20}    # seconds between samples

rm -f wp3_boot/gdb_sample.txt
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 1G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/dev/null \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1

# run to btext
timeout 30 $GDB -batch -ex "set pagination off" \
  -ex "target remote localhost:1234" \
  -ex "break *0xffffffff9e642a90" -ex "continue" -ex "delete" \
  >/dev/null 2>&1

sleep $WAIT1
sample() {
  timeout 25 $GDB -batch -ex "set pagination off" \
    -ex "target remote localhost:1234" \
    -ex "info registers rip rsp rbp rbx r12 r13 r14 r15 rax rcx rdx rsi rdi r8 r9" \
    -ex "echo \\n=== CODE AT RIP ===\\n" \
    -ex "x/20i \$rip" \
    -ex "echo \\n=== STACK ===\\n" \
    -ex "x/24gx \$rsp" \
    -ex "detach" 2>/dev/null
}
{
  echo "########## SAMPLE 1 (t+${WAIT1}s) ##########"
  sample
  sleep $WAIT2
  echo "########## SAMPLE 2 (t+$((WAIT1+WAIT2))s) ##########"
  sample
} >> wp3_boot/gdb_sample.txt 2>&1 &

wait $! 2>/dev/null
kill $QPID 2>/dev/null; wait 2>/dev/null
echo "=== gdb_sample.txt ==="
cat wp3_boot/gdb_sample.txt
