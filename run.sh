#!/bin/bash
# ============================================================================
# PS5 13.60 kernel — QEMU boot (WP7 kit)
# Usage:  bash run.sh [seconds]
# Needs:  qemu-system-x86_64 (any version >= 6; BIOS files bundled in ./bios)
# ============================================================================
cd "$(dirname "$0")"
TMO=${1:-240}

# QEMU detection
QEMU=${QEMU:-$(command -v qemu-system-x86_64 || true)}
[ -z "$QEMU" ] && [ -x /usr/lib/qemu/qemu-system-x86_64 ] && QEMU=/usr/lib/qemu/qemu-system-x86_64
if [ -z "$QEMU" ] && [ -x ../qemu-local/root/usr/bin/qemu-system-x86_64 ]; then
  QEMU=$(cd .. && pwd)/qemu-local/root/usr/bin/qemu-system-x86_64
  export LD_LIBRARY_PATH=$(cd .. && pwd)/qemu-local/root/usr/lib/x86_64-linux-gnu
fi

[ -x "$QEMU" ] || { echo "qemu-system-x86_64 not found — install qemu-system-x86"; exit 1; }
[ -f wp3_boot/trampoline.elf ] || { echo "missing wp3_boot/trampoline.elf"; exit 1; }

# Auto-build kernel if missing
if [ ! -f wp3_boot/kernel_raw.bin ]; then
    echo "[*] wp3_boot/kernel_raw.bin not found! Auto-building..."
    bash ./fetch_and_build.sh || exit 1
fi

rm -f serial.log

$QEMU -L ./bios \
  -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=serial.log \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot 2>/dev/null &
QPID=$!

# stop early after 45s of silence (kernel alive-but-quiet or halted)
last=0; quiet=0
for i in $(seq 1 $TMO); do
  sleep 1
  kill -0 $QPID 2>/dev/null || break
  sz=$(stat -c%s serial.log 2>/dev/null || echo 0)
  if [ "$sz" = "$last" ]; then
    quiet=$((quiet+1)); [ $quiet -ge 45 ] && [ "$sz" -gt 200 ] && break
  else
    quiet=0; last=$sz
  fi
done
kill $QPID 2>/dev/null; wait 2>/dev/null

echo "=== serial.log: $(stat -c%s serial.log) bytes ==="
echo "=== tail ==="
tail -25 serial.log
