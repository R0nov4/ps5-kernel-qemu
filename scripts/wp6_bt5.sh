#!/bin/bash
# WP6-BT5: at the PT-window fill write (0x9ece1c30), dump the table entry
# and inputs to determine the correct data patch.
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64

cat > /tmp/wp6_bt5.gdb <<'EOF'
set pagination off
set confirm off
set height 0
target remote localhost:1234
hbreak *0xffffffff9ece1c30
continue
printf "\n=== AT PT-FILL WRITE (first hit) ===\n"
info registers rax rbx rcx rdx rsi rdi r10 r11 r12 r13 r14 r15 rbp rsp
printf "\n--- table entry @ rbx ---\n"
x/14gx $rbx
printf "\n--- r13 (phys input) region descriptor ---\n"
x/8gx $r13
printf "\n--- the window table @ 0xa1f37e90 (first 3 entries) ---\n"
x/42gx 0xffffffffa1f37e90
kill
EOF

rm -f wp3_boot/wp6_bt5.log
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 2G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/dev/null \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout 100 $GDB -batch -x /tmp/wp6_bt5.gdb > wp3_boot/wp6_bt5.log 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null
grep -av "warning:" wp3_boot/wp6_bt5.log | head -60
