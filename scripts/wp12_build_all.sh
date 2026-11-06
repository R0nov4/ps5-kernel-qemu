#!/bin/bash
# ============================================================================
# WP12 — full reproducible build of the PS5 13.60 boot kit
# pristine WP7 image -> WP9 (W1..W10) + MADT loop fix + WP11 crash-fix series
#   + WP12: cave v4 (true-NULL return)
#           caller canonical-VA guard @0x9e82fce2
#           walker NULL-object guard (stage-49 'fakepg' CR2=0x18)
#           stage-48 PREINIT_POOL->UMA converter stub (fn8 @0x9ebd7b40)
# usage: bash scripts/wp12_build_all.sh [--no-stub48]
# ============================================================================
set -e
set -o pipefail
cd .
S=./scripts
K=./kit_build

# pristine base location: kit_build/pristine/ (survives kit-zip replacement)
# fallback: extract from download/ps5_boot_kit.zip while it still hashes f242f55e
mkdir -p $K/pristine
if [ ! -f $K/pristine/kernel_raw.bin ]; then
  unzip -o -j download/ps5_boot_kit.zip wp3_boot/kernel_raw.bin wp3_boot/trampoline.elf -d $K/pristine/ > /dev/null
fi
BASE_HASH=$(sha256sum $K/pristine/kernel_raw.bin | cut -d' ' -f1)
if [ "${BASE_HASH:0:8}" != "f242f55e" ]; then
  echo "!! pristine base lost (hash $BASE_HASH) — cannot rebuild"; exit 1
fi

echo "=== [0] restore pristine WP7 base (P1..P11) from kit_build/pristine ==="
rm -f $K/wp3_boot/kernel_raw.bin $K/wp3_boot/trampoline.elf
mkdir -p $K/wp3_boot
cp $K/pristine/kernel_raw.bin $K/pristine/trampoline.elf $K/wp3_boot/
echo "pristine base OK (f242f55e...)"

echo "=== [1] WP9 kernel patches (W1..W10) + WP10 MADT loop fix ==="
python3 -u $S/wp9_patch_kernel.py | tail -3

echo "=== [2] WP9 trampoline patches (rsdp_scan NOPs, gate check) ==="
python3 -u $S/wp9_patch_trampoline.py | tail -3

echo "=== [3] WP11: wipe 36 residue seed-area pointers ==="
python3 -u $S/wp11_fix_queues.py > $S/fixq.log 2>&1
grep -c "wipe 0x" $S/fixq.log | xargs echo "wiped:"

echo "=== [3b] WP12 fix #4: wipe below/above-kernel DMAP residue (cold-boot semantics) ==="
python3 -u $S/wp12_wipe_dmaplow.py | tail -4

echo "=== [3c] WP12 fix #6: relocate mDBG state base to fresh-zero seed page ==="
python3 -u $S/wp12_fix_mdbg_state.py | tail -2

echo "=== [3d] WP12 fix #7: relocate 'intr sources' registry context ==="
python3 -u $S/wp12_fix_intr_ctx.py | tail -2

echo "=== [10c] WP12 fix #8: free-lock no-op guard in unlock retry loop ==="
python3 -u $S/wp12_patch_unlock_guard.py | tail -3

echo "=== [10d] WP12 fix #10: allocator NULL-zone guard @0x9e82b880 + caller NULL-routing ==="
python3 -u $S/wp12_patch_allocnull_guard.py | tail -3


echo "=== [4] WP11 fix: mtx_lock zero-lock force-acquire ==="
python3 -u $S/wp11_patch_mtx.py | tail -2

echo "=== [5] WP11 fix: fn1 null-callback guard ==="
python3 -u $S/wp11_patch_fn1.py | tail -1

echo "=== [6] WP11 fix: tail-jmp NULL guard ==="
python3 -u $S/wp11_patch_tailjmp.py | tail -1

echo "=== [7] WP11 fix: fn1 bogus-object cave (jump site + cave v1) ==="
python3 -u $S/wp11_patch_bogusobj.py | tail -2

echo "=== [8] WP12 fix #1: cave v4 — bogus branch zeroes rbx (true NULL) ==="
python3 -u $S/wp12_patch_cave_v4.py | tail -3

echo "=== [9] WP12 fix #2: caller canonical-VA guard @0x9e82fce2 ==="
python3 -u $S/wp12_patch_caller_guard.py | tail -3

echo "=== [10] WP12 fix #3: walker NULL-object guard (stage-49 fakepg) ==="
python3 -u $S/wp12_patch_walker_null.py | tail -3

echo "=== [10b] WP12 fix #5: hash-lookup bucket guard @0x9e9467ea ==="
python3 -u $S/wp12_patch_bucket_guard.py | tail -3

if [ "$1" != "--no-stub48" ]; then
  echo "=== [11] WP12: stub stage-48 PREINIT_POOL converter (redundant re-run) ==="
  python3 -u $S/wp12_stub_preinit.py | tail -2
else
  echo "=== [11] SKIPPED stage-48 stub (--no-stub48) ==="
fi

echo "=== [12] WP11 fix: SMAP — reserve the seed area (trampoline mmap_fix) ==="
python3 -u $S/wp11_patch_smap.py | tail -3

# NOTE: zone_seed / CAVE6 (@0x3F00E000 + 0x9EE30800) was REMOVED — it regressed
# the boot back into the fn3<->fn1 loop before sysctl. Do NOT re-add.

echo "=== [13] verification boot ==="
cd $K && bash run.sh 300 > /dev/null 2>&1 || true
grep -a -m1 "SIE CONFIDENTIAL" serial.log || echo "!! banner missing"
grep -a -m1 "Memory mode" serial.log || echo "!! Memory mode missing"
grep -a -m1 "instruction pointer" serial.log || true
grep -a -c "sysctl" serial.log | xargs echo "sysctl lines:"
echo "=== WP12 build complete ==="
