#!/bin/bash
# WP4: console-chain GDB hunt v2 (gdb command file)
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64

cat > /tmp/chain.gdb <<'EOF'
set pagination off
target remote localhost:1234
break *0xffffffff9e64d410
break *0xffffffff9e89d890
break *0xffffffff9e739bc0
break *0xffffffff9e7df4a0
break *0xffffffff9e7df4b0
break *0xffffffff9e7df230
break *0xffffffff9ee30cb6
break *0xffffffff9ebe0dca
break *0xffffffff9e85e2f0
continue
printf "\n=== STOP 1 ===\n"
info registers rip rdi rsi rbx
x/s $rdi
continue
printf "\n=== STOP 2 ===\n"
info registers rip rdi rsi rbx
x/s $rdi
continue
printf "\n=== STOP 3 ===\n"
info registers rip rdi rsi rbx
x/s $rdi
continue
printf "\n=== STOP 4 ===\n"
info registers rip rdi rsi rbx
x/s $rdi
continue
printf "\n=== STOP 5 ===\n"
info registers rip rdi rsi rbx
x/s $rdi
continue
printf "\n=== STOP 6 ===\n"
info registers rip rdi rsi rbx
x/s $rdi
continue
printf "\n=== STOP 7 ===\n"
info registers rip rdi rsi rbx
x/s $rdi
continue
printf "\n=== STOP 8 ===\n"
info registers rip rdi rsi rbx
x/s $rdi
continue
printf "\n=== STOP 9 ===\n"
info registers rip rdi rsi rbx
x/s $rdi
continue
printf "\n=== STOP 10 ===\n"
info registers rip rdi rsi rbx
x/s $rdi
continue
printf "\n=== STOP 11 ===\n"
info registers rip rdi rsi rbx
continue
printf "\n=== STOP 12 ===\n"
info registers rip rdi rsi rbx
x/s $rdi
printf "\n=== LOCALS ===\n"
x/4gx $rbp-0x48
info registers r15 r12 rax rcx
kill
EOF

rm -f wp3_boot/gdb_chain.txt
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 1G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/dev/null \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout 120 $GDB -batch -x /tmp/chain.gdb > wp3_boot/gdb_chain.txt 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null
grep -A6 "=== STOP" wp3_boot/gdb_chain.txt | head -130
