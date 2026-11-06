#!/bin/bash
# WP5: hunt the phys-0 (IVT) read — rwatch DMAP(0) + garbage-jump catch
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64

cat > /tmp/ivt.gdb <<'EOF'
set pagination off
set confirm off
target remote localhost:1234
hbreak *0xffffffff9edfd670
continue
printf "\n=== REGION FN ENTRY 0x9edfd670 ===\n"
info registers rip rsp rbp rdi rsi rdx rcx r8 r9 r13 r15
x/4gx $rsp
printf "caller retaddr:\n"
x/1gx $rsp
delete 1
rwatch *(unsigned long long *)0xffff8e7700000000
hbreak *0xc0007240f000ff53
continue
printf "\n=== HIT A ===\n"
info registers rip rsp rbp rax rbx rcx rdx rsi rdi r8 r9 r10 r11 r12 r13 r14 r15
x/6i $pc-12
x/20gx $rsp
continue
printf "\n=== HIT B ===\n"
info registers rip rsp rbp rax rbx rcx rdx rsi rdi r8 r9
x/6i $pc-12
x/20gx $rsp
continue
printf "\n=== HIT C ===\n"
info registers rip rsp rbp rax rbx rcx rdx rsi rdi r8 r9
x/6i $pc-12
x/20gx $rsp
continue
printf "\n=== HIT D ===\n"
info registers rip rsp rbp rax rbx rcx rdx rsi rdi r8 r9
x/6i $pc-12
x/20gx $rsp
kill
EOF

rm -f wp3_boot/gdb_ivt.txt
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 1G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/dev/null \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout 280 $GDB -batch -x /tmp/ivt.gdb > wp3_boot/gdb_ivt.txt 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null
grep -vE "^(warning|0x000000000000fff0|\[Inferior|Kill)" wp3_boot/gdb_ivt.txt | head -170
