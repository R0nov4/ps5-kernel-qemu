#!/bin/bash
# WP5e: catch the writer of pmap global [0xa1f38378] + inspect the #GP write
# at 0x9eccc6e3 (mov %rdx,(%rcx,%r8,8)) with live register/table state.
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64

cat > /tmp/pm.gdb <<'EOF'
set pagination off
set confirm off
target remote localhost:1234
hbreak *0xffffffff9e642a90
continue
printf "\n=== BTEXT — watching [0xa1f38378] ===\n"
delete
watch *(unsigned long long *)0xffffffffa1f38378
hbreak *0xffffffff9eccc6bf
hbreak *0xffffffff9eccc6e3
continue
printf "\n=== HIT 1 (writer or loop) ===\n"
info registers rip rsp rbp rax rbx rcx rdx rsi rdi r8
x/4i $pc-8
continue
printf "\n=== HIT 2 ===\n"
info registers rip rsp rax rcx rdx rsi rdi r8
x/4i $pc-8
continue
printf "\n=== HIT 3 ===\n"
info registers rip rsp rax rcx rdx rsi rdi r8
x/4i $pc-8
continue
printf "\n=== HIT 4 ===\n"
info registers rip rsp rax rcx rdx rsi rdi r8
x/4i $pc-8
continue
printf "\n=== HIT 5 (hopefully the write site) ===\n"
info registers rip rsp rbp rax rbx rcx rdx rsi rdi r8 r9
x/6i $pc-12
printf "live [0xa1f38378] = "
x/gx 0xffffffffa1f38378
printf "live [0x9fe4d498] = "
x/gx 0xffffffff9fe4d498
printf "write target VA (rcx + r8*8):\n"
p/x $rcx + $r8*8
kill
EOF

rm -f wp3_boot/gdb_pm.txt
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 1G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/dev/null \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout 280 $GDB -batch -x /tmp/pm.gdb > wp3_boot/gdb_pm.txt 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null
grep -vE "^(warning|0x000000000000fff0|\[Inferior|Kill)" wp3_boot/gdb_pm.txt | head -140
