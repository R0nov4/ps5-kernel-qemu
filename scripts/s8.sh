#!/bin/bash
# WP5b: hunt the IVT read at VA 0 (identity map window: btext -> CR3 switch)
# rwatch armed exactly at btext: any read of the qword at VA 0 / VA 0x40
# (= BIOS IVT through the trampoline identity mapping) gets caught with
# full register/stack context — that is the origin of 0xc0007240f000ff53.
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64

cat > /tmp/ivt2.gdb <<'EOF'
set pagination off
set confirm off
target remote localhost:1234
hbreak *0xffffffff9e642a90
continue
printf "\n=== BTEXT REACHED — arming IVT watches ===\n"
delete
rwatch *(unsigned long long *)0x0
rwatch *(unsigned long long *)0x40
hbreak *0xc0007240f000ff53
continue
printf "\n=== HIT A (first read of VA0/VA0x40 OR garbage jump) ===\n"
info registers rip rsp rbp rax rbx rcx rdx rsi rdi r8 r9 r10 r11 r12 r13 r14 r15
x/8i $pc-16
x/16gx $rsp
continue
printf "\n=== HIT B ===\n"
info registers rip rsp rbp rax rbx rcx rdx rsi rdi r8 r9
x/8i $pc-16
x/16gx $rsp
continue
printf "\n=== HIT C ===\n"
info registers rip rsp rbp rax rbx rcx rdx rsi rdi r8 r9
x/8i $pc-16
x/16gx $rsp
continue
printf "\n=== HIT D ===\n"
info registers rip rsp rbp rax rbx rcx rdx rsi rdi r8 r9
x/8i $pc-16
x/16gx $rsp
kill
EOF

rm -f wp3_boot/gdb_ivt2.txt
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 1G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/dev/null \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout 280 $GDB -batch -x /tmp/ivt2.gdb > wp3_boot/gdb_ivt2.txt 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null
grep -vE "^(warning|0x000000000000fff0|\[Inferior|Kill)" wp3_boot/gdb_ivt2.txt | head -180
