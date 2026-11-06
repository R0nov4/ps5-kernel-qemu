#!/bin/bash
# WP4: final GDB hunt — identify looping DELAY caller + console drop point
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64

cat > /tmp/hunt4.gdb <<'EOF'
set pagination off
target remote localhost:1234
hbreak *0xffffffff9e642a90
continue
delete
break *0xffffffff9e85e1e0
break *0xffffffff9ebe0dba
break *0xffffffff9e64d410
break *0xffffffff9e89f4f1
break *0xffffffff9e89d890
break *0xffffffff9e739bc0
continue
printf "\n=== STOP 1 ===\n"
info registers rip rdi rsi rax rcx
x/8gx $rsp
continue
printf "\n=== STOP 2 ===\n"
info registers rip rdi rsi rax rcx
x/8gx $rsp
continue
printf "\n=== STOP 3 ===\n"
info registers rip rdi rsi rax rcx
x/8gx $rsp
continue
printf "\n=== STOP 4 ===\n"
info registers rip rdi rsi rax rcx
x/8gx $rsp
continue
printf "\n=== STOP 5 ===\n"
info registers rip rdi rsi rax rcx
x/8gx $rsp
continue
printf "\n=== STOP 6 ===\n"
info registers rip rdi rsi rax rcx
x/8gx $rsp
continue
printf "\n=== STOP 7 ===\n"
info registers rip rdi rsi rax rcx
x/8gx $rsp
continue
printf "\n=== STOP 8 ===\n"
info registers rip rdi rsi rax rcx
x/8gx $rsp
continue
printf "\n=== STOP 9 ===\n"
info registers rip rdi rsi rax rcx
x/8gx $rsp
kill
EOF

rm -f wp3_boot/gdb_hunt4.txt
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 1G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/dev/null \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout 100 $GDB -batch -x /tmp/hunt4.gdb > wp3_boot/gdb_hunt4.txt 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null
grep -vE "^(warning|0x000000000000fff0|\\[Inferior|Breakpoint [0-9]+ at|Kill)" wp3_boot/gdb_hunt4.txt | head -140
