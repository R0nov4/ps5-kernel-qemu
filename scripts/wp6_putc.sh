#!/bin/bash
# WP6-DIAG B (v2): putchar probe — is ANY printf happening?
# All breakpoints+commands defined BEFORE continue. First putchar hit
# prints char + backtrace, then bp removed; run continues to timeout.
# Usage: bash wp3_boot/wp6_putc.sh [run_seconds=90]
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
T=${1:-90}

cat > /tmp/wp6_putc.gdb <<'EOF'
set pagination off
set confirm off
set height 0
target remote localhost:1234
break *0xffffffff9e89d890
commands 1
silent
printf "\n>>> PUTCHAR HIT char=%d (%c)\n", (int)($rdi & 0xff), (char)($rdi & 0xff)
bt 10
delete 1
continue
end
hbreak *0xffffffff9e9261f0
commands 2
silent
printf "\n=== MI_STARTUP ENTERED ===\n"
printf "putchar patch @0x9e89d8a1 (expect 90 90): "
x/2bx 0xffffffff9e89d8a1
delete 2
continue
end
continue
EOF

rm -f wp3_boot/wp6_putc.log
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 2G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/dev/null \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout $T $GDB -batch -x /tmp/wp6_putc.gdb > wp3_boot/wp6_putc.log 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null

echo "=== putchar hits ==="
grep -ac "PUTCHAR HIT" wp3_boot/wp6_putc.log
echo "=== log (filtered) ==="
grep -av "warning:" wp3_boot/wp6_putc.log | head -40
