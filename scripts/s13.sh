#!/bin/bash
# WP5f: full register + runtime-entry dump exactly at the translation
# 0x9eccc575..0x9eccc578 that computes the garbage table pointer.
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64

cat > /tmp/pm2.gdb <<'EOF'
set pagination off
set confirm off
target remote localhost:1234
hbreak *0xffffffff9eccc575
continue
printf "\n=== AT 0x9eccc575 (translation complete, before store) ===\n"
info registers rip rsp rbp rax rbx rcx rdx rsi rdi r8 r9 r10 r11 r12 r13 r14 r15
printf "result rsi (to be stored): 0x"
p/x $rsi
printf "rbx struct (region descriptor, DMAP): 0x"
p/x $rbx
printf "[rbx+0x8d] (domain index byte): "
x/1bx $rbx+0x8d
printf "entry rdx (runtime fields):\n"
x/14gx $rdx
printf "r13 (multiplier): 0x"
p/x $r13
printf "r14 (target): 0x"
p/x $r14
printf "rdi (region base): 0x"
p/x $rdi
printf "rbx+0x60 area (region desc):\n"
x/16gx $rbx+0x40
kill
EOF

rm -f wp3_boot/gdb_pm2.txt
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 1G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/dev/null \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout 280 $GDB -batch -x /tmp/pm2.gdb > wp3_boot/gdb_pm2.txt 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null
grep -vE "^(warning|0x000000000000fff0|\[Inferior|Kill)" wp3_boot/gdb_pm2.txt | head -80
