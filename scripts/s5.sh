#!/bin/bash
# ============================================================================
# WP3-STEP 5: MSR/CFI/console-neutralized boot  →  FIRST REAL PS5 KERNEL TEXT
# Self-contained: rebuild patches → trampoline → QEMU boot → serial.log
# Usage:  bash wp3_boot/s5.sh [timeout_sec=150]
# Requires nothing outside . (local QEMU + nasm + ld).
# ============================================================================
set -e
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
export PATH=./qemu-local/root/usr/bin:$PATH
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
T=${1:-150}

echo "[1/3] building patch table (572 patches: 49 boot + cfi-ret + putc-stubs + stub-or-nop + 37 wrmsr + 481 rdmsr)..."
python3 scripts/wp3_5_build.py > /tmp/wp3_5_build.log 2>&1 || { tail -5 /tmp/wp3_5_build.log; exit 1; }
grep -E "TOTAL PATCHES|user site" /tmp/wp3_5_build.log

echo "[2/3] assembling trampoline..."
nasm -f elf32 -I wp3_boot/ -o wp3_boot/trampoline.o scripts/trampoline.asm
ld -m elf_i386 -T wp3_boot/tramp.ld -o wp3_boot/trampoline.elf wp3_boot/trampoline.o 2>/dev/null

echo "[3/3] booting PS5 13.60 kernel (timeout ${T}s)..."
rm -f wp3_boot/serial.log
set +e
timeout $T $QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=wp3_boot/serial.log \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot 2>/dev/null
RC=$?
set -e
echo "=== qemu exit code: $RC  (124 = timeout, kernel still running) ==="
echo "=== serial.log (from PS5-TRAMPOLINE onward) ==="
grep -n "PS5-TRAMPOLINE" wp3_boot/serial.log | head -1
sed -n "$(grep -n 'PS5-TRAMPOLINE' wp3_boot/serial.log | head -1 | cut -d: -f1),\$p" wp3_boot/serial.log 2>/dev/null | head -120
