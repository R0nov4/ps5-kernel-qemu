#!/bin/bash
# WP6-STEP: single-step 40 instructions from the stuck RIP to see where
# execution actually goes (tight loop? interrupt handler? fault path?).
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64

cat > /tmp/wp6_step.gdb <<'EOF'
set pagination off
set confirm off
set height 0
target remote localhost:1234
hbreak *0xffffffff9ea65fff
continue
printf "\n=== AT STUCK RIP — registers ===\n"
info registers rip rsi rdi r10 r11 r12 rbx rbp rdx rcx r8 r9 rax
printf "\n=== 60 single steps ===\n"
set $i = 0
while $i < 60
  stepi
  printf "%3d rip=%p rsi=%p r10=%p\n", $i, $rip, $rsi, $r10
  set $i = $i + 1
end
kill
EOF

rm -f wp3_boot/wp6_step.log
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 2G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/dev/null \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout 110 $GDB -batch -x /tmp/wp6_step.gdb > wp3_boot/wp6_step.log 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null
grep -a "rip=\|AT STUCK\|rsi\|r10\|===" wp3_boot/wp6_step.log | head -80
