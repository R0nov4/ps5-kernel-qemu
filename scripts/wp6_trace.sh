#!/bin/bash
# WP6-DIAG A: live SYSINIT stamp trace.
# Breakpoint on the done-stamp write (mi_startup 0x9e926337 'mov [rax],1')
# logs every executed sysinit entry => exact boot progress + which funcs run.
# Usage: bash wp3_boot/wp6_trace.sh [run_seconds=100]
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
T=${1:-100}

cat > /tmp/wp6_trace.gdb <<'EOF'
set pagination off
set confirm off
set height 0
target remote localhost:1234
hbreak *0xffffffff9e9261f0
continue
printf "\n=== MI_STARTUP ENTERED ===\n"
printf "putchar patch @0x9e89d8a1 (expect 90 90): "
x/2bx 0xffffffff9e89d8a1
printf "sysinit cursor [0xffffffffa19781b0]: "
x/1gx 0xffffffffa19781b0
printf "sysinit end    [0xffffffffa19781a8]: "
x/1gx 0xffffffffa19781a8
delete 1
break *0xffffffff9e926337
commands
silent
printf "STAMP entry=%p sub=%d fn=%p udata=%p\n", $rax, *(int*)$rax, *(void**)($rax+8), *(void**)($rax+0x10)
continue
end
continue
EOF

rm -f wp3_boot/wp6_trace.log
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 2G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/dev/null \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout $T $GDB -batch -x /tmp/wp6_trace.gdb > wp3_boot/wp6_trace.log 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null

echo "=== stamp trace (first 40) ==="
grep -a "STAMP\|MI_STARTUP\|putchar patch\|cursor\|end " wp3_boot/wp6_trace.log | head -46
echo "=== total stamps logged ==="
grep -ac "STAMP" wp3_boot/wp6_trace.log
echo "=== last 5 stamps ==="
grep -a "STAMP" wp3_boot/wp6_trace.log | tail -5
