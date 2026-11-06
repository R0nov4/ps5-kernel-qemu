#!/bin/bash
# WP6-BT: break at sscanf-engine thunk (0x9e65b880), dump args + backtrace
# for the first 6 calls. Top-level gdb commands only (no commands-blocks).
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64

cat > /tmp/wp6_bt.gdb <<'EOF'
set pagination off
set confirm off
set height 0
target remote localhost:1234
hbreak *0xffffffff9e65b880
set $n = 0
while $n < 6
  continue
  printf "\n=== ENGINE CALL #%d ===\n", $n
  info registers rdi rsi rdx rcx r8 r9 r10 r11 r12 r13 r14 r15 rsp rbp
  printf "fmt str @rsi: "
  x/s $rsi
  printf "input str @rdi: "
  x/s $rdi
  bt 14
  printf "stack: "
  x/12gx $rsp
  set $n = $n + 1
end
kill
EOF

rm -f wp3_boot/wp6_bt.log
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 2G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/dev/null \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout 120 $GDB -batch -x /tmp/wp6_bt.gdb > wp3_boot/wp6_bt.log 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null
grep -av "^warning" wp3_boot/wp6_bt.log | head -120
