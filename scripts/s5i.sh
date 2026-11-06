#!/bin/bash
# WP4: master GDB hunt v3 — correct 3-phase breakpoints + TSC dynamics
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64

cat > /tmp/hunt3.gdb <<'EOF'
set pagination off
target remote localhost:1234
# phase 1: hardware bp at btext (works pre-load)
hbreak *0xffffffff9e642a90
continue
printf "\n=== AT BTEXT (kernel loaded+mapped) ===\n"
info registers rip rsp
delete
# phase 2: software bps now that memory is mapped
break *0xffffffff9e64d410
break *0xffffffff9e89d890
break *0xffffffff9e739bc0
break *0xffffffff9e7df4a0
break *0xffffffff9e7df4b0
break *0xffffffff9ebe0dca
break *0xffffffff9e85e2f0
break *0xffffffff9e85e420
continue
printf "\n=== STOP A ===\n"
info registers rip rdi rsi rbx rax
x/s $rdi
continue
printf "\n=== STOP B ===\n"
info registers rip rdi rsi rbx rax
x/s $rdi
continue
printf "\n=== STOP C ===\n"
info registers rip rdi rsi rbx rax
x/s $rdi
continue
printf "\n=== STOP D ===\n"
info registers rip rdi rsi rbx rax
x/s $rdi
continue
printf "\n=== STOP E (delay loop?) ===\n"
info registers rip rdi rsi rbx rax
printf "\n=== LOOP LOCALS ===\n"
x/4gx $rbp-0x48
info registers r15 r12 rax rcx
printf "\n=== GATE GLOBALS ===\n"
x/gx 0xffffffffa1e382e0
x/gx 0xffffffffa1e36dc8
x/gx 0xffffffffa1e36dc0
x/gx 0xffffffffa1e36dd8
printf "\n=== TSC DYNAMIC TEST (5s apart) ===\n"
delete
break *0xffffffff9e85e2f0
continue
info registers r15 r12 rax
continue
info registers r15 r12 rax
delete
break *0xffffffff9e85e420
continue
info registers rip rdx rax
x/2i $rip
si
si
printf "\n--- after rdtsc #1 ---\n"
info registers rdx rax
delete
break *0xffffffff9e85e420
continue
si
si
printf "\n--- after rdtsc #2 (should differ) ---\n"
info registers rdx rax
kill
EOF

rm -f wp3_boot/gdb_hunt3.txt
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 1G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/dev/null \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout 110 $GDB -batch -x /tmp/hunt3.gdb > wp3_boot/gdb_hunt3.txt 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null
cat wp3_boot/gdb_hunt3.txt | grep -vE "^(warning|0x000000000000fff0|\\[Inferior|Breakpoint [0-9]+ at)" | head -150
