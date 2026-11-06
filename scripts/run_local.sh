#!/bin/bash
# ============================================================================
# run_local.sh — portable PS5 13.60 kernel boot (no . deps)
#
# USAGE:
#   bash run_local.sh [timeout_sec] [path/to/ps5_kernel_1360_reconstructed.elf]
#
# Requirements (Debian/Ubuntu):  sudo apt install qemu-system-x86 nasm binutils
#   python3 (stdlib only — no capstone needed for this path)
#
# Flow:
#   [1] make_kernel_raw.py  — ELF -> wp3_boot/kernel_raw.bin (flat phys image)
#   [2] nasm + ld           — build wp3_boot/trampoline.elf from scripts/trampoline.asm
#                              (includes wp3_boot/{patches,params,meta}.inc)
#   [3] qemu-system-x86_64  — TCG boot, serial -> wp3_boot/serial.log via debugcon 0x402
#
# NOTE ON KVM: run WITHOUT -enable-kvm first. The neutralized MSR stubs make
# TCG safe on the reference QEMU (unknown MSRs read as 0). Under KVM a
# different host/QEMU may still #GP on the remaining unpatched rdmsr sites —
# if you want speed, try adding -enable-kvm and compare the serial log.
# ============================================================================
set -e
cd "$(dirname "$0")"

T=${1:-150}
ELF=${2:-}
if [ -z "$ELF" ]; then
    for c in ./ps5_kernel_1360_reconstructed.elf ../ps5_kernel_1360_reconstructed.elf \
             ./download/ps5_kernel_1360_reconstructed.elf; do
        [ -f "$c" ] && ELF="$c" && break
    done
fi
if [ -z "$ELF" ] || [ ! -f "$ELF" ]; then
    echo "ERROR: ps5_kernel_1360_reconstructed.elf not found."
    echo "  Unzip ps5_kernel_1360.zip next to this kit (or pass its path as arg 2)."
    exit 1
fi

echo "[1/3] building kernel_raw.bin from: $ELF"
python3 make_kernel_raw.py "$ELF" wp3_boot/kernel_raw.bin

PC=$(grep -o "PATCH_COUNT equ [0-9]*" wp3_boot/patches.inc | grep -o "[0-9]*")
echo "[2/3] assembling trampoline (${PC} in-memory patches)..."
nasm -f elf32 -I wp3_boot/ -o wp3_boot/trampoline.o scripts/trampoline.asm
ld -m elf_i386 -T wp3_boot/tramp.ld -o wp3_boot/trampoline.elf wp3_boot/trampoline.o

echo "[3/3] booting PS5 13.60 kernel (TCG, timeout ${T}s)..."
rm -f wp3_boot/serial.log
set +e
timeout "$T" qemu-system-x86_64 \
  -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=wp3_boot/serial.log \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot 2>/dev/null
RC=$?
set -e
echo "=== qemu exit code: $RC  (124 = timeout, kernel still running) ==="
echo "=== serial.log from PS5-TRAMPOLINE onward ==="
L=$(grep -an "PS5-TRAMPOLINE" wp3_boot/serial.log | head -1 | cut -d: -f1)
if [ -n "$L" ]; then
    tail -n +$L wp3_boot/serial.log | head -120
else
    echo "(no trampoline output — check qemu/serial setup)"
    head -5 wp3_boot/serial.log 2>/dev/null
fi
