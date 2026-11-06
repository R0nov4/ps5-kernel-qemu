#!/bin/bash
# ============================================================================
# WP11 — full reproducible build of the PS5 13.60 boot kit
# pristine WP7 image -> WP9 (W1..W10) + MADT loop fix + WP11 crash-fix series
# ============================================================================
set -e
cd .
S=./scripts
K=./kit_build

echo "=== [0] restore pristine WP7 base (P1..P11) from the kit zip ==="
rm -f $K/wp3_boot/kernel_raw.bin $K/wp3_boot/trampoline.elf
unzip -o -j download/ps5_boot_kit.zip wp3_boot/kernel_raw.bin wp3_boot/trampoline.elf -d $K/wp3_boot/ > /dev/null
sha256sum $K/wp3_boot/kernel_raw.bin | grep -q f242f55e || { echo "base hash mismatch!"; exit 1; }
echo "pristine base OK (f242f55e...)"

echo "=== [1] WP9 kernel patches (W1..W10) + WP10 MADT loop fix ==="
python3 -u $S/wp9_patch_kernel.py | tail -3

echo "=== [2] WP9 trampoline patches (rsdp_scan NOPs, gate check) ==="
python3 -u $S/wp9_patch_trampoline.py | tail -3

echo "=== [3] WP11: wipe 36 residue seed-area pointers ==="
python3 -u $S/wp11_fix_queues.py > $S/fixq.log 2>&1
grep -c "wipe 0x" $S/fixq.log | xargs echo "wiped:"

echo "=== [4] WP11 fix: mtx_lock zero-lock force-acquire ==="
python3 -u $S/wp11_patch_mtx.py | tail -2

echo "=== [5] WP11 fix: fn1 null-callback guard ==="
python3 -u $S/wp11_patch_fn1.py | tail -1

echo "=== [6] WP11 fix: tail-jmp NULL guard ==="
python3 -u $S/wp11_patch_tailjmp.py | tail -1

echo "=== [7] WP11 fix: fn1 bogus-object cave guard ==="
python3 -u $S/wp11_patch_bogusobj.py | tail -2
# rewrite the cave: displaced write inside + canonical-VA guard (v3)
python3 - <<'EOF'
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
KTEXT = 0x9E3F0000
CAVE = 0x9EE30400
ASM = """
mov r13, qword ptr [rbp - 0x40]
movabs rax, 0xffff000000000000
cmp rbx, rax
jb bogus
mov qword ptr [rbx], r14
movabs rax, 0xffffffff9e82d942
jmp rax
bogus:
movabs rax, 0xffffffff9e82d979
jmp rax
"""
ks = Ks(KS_ARCH_X86, KS_MODE_64)
enc, _ = ks.asm(ASM, CAVE)
img = bytearray(open("./kit_build/wp3_boot/kernel_raw.bin", "rb").read())
off = CAVE - KTEXT
img[off:off+len(enc)] = bytes(enc)
open("./kit_build/wp3_boot/kernel_raw.bin", "wb").write(img)
print("cave v3 written (canonical-VA guard + displaced write)")
EOF

echo "=== [8] WP11 fix: SMAP — reserve the seed area (trampoline mmap_fix) ==="
python3 -u $S/wp11_patch_smap.py | tail -3

echo "=== [9] verification boot ==="
cd $K && bash run.sh 300 > /dev/null 2>&1 || true
grep -a -m1 "SIE CONFIDENTIAL" serial.log || echo "!! banner missing"
grep -a -m1 "instruction pointer" serial.log || true
echo "=== build complete ==="
