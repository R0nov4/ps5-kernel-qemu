#!/bin/bash
# WP18 Phase A (continue) — apply WP17 #1..#8 on the built WP16 image + boot
set -e
set -o pipefail
cd .
S=./scripts
K=./kit_build

echo "=== [1] WP17 #1/#2/#3 zone-drain guard (cave63/64 + zone-table seed) ==="
python3 -u $S/wp17_patch_zonedrain_guard.py | tail -2
echo "=== [2] WP17 #4 kmem thunk read-time fallback (cave65) ==="
python3 -u $S/wp17_patch_kmem_thunk.py | tail -1
echo "=== [3] WP17 #5 W1 v3 vm_page supply extension (cave66) ==="
python3 -u $S/wp17_patch_w1_extend.py | tail -1
echo "=== [4] WP17 #6 malloc bump window 380KB -> 5.6MB (caves 50/56/51) ==="
python3 -u $S/wp17_patch_malloc_window.py | tail -2
echo "=== [5] WP17 #7 cave57 exit retarget (td_locks double-unlock) ==="
python3 -u $S/wp17_patch_cave57_retarget.py | tail -1
echo "=== [6] WP17 #8 kmem-arena lazy bootstrap (cave67) ==="
python3 -u $S/wp17_patch_kmem_arena_boot.py | tail -1

echo "=== [7] size sanity (must equal pristine 65224704) ==="
SZ=$(stat -c%s $K/wp3_boot/kernel_raw.bin)
echo "kernel_raw.bin size: $SZ"
[ "$SZ" = "65224704" ] || { echo "!! SIZE MISMATCH — aborting"; exit 1; }

echo "=== [8] ROLLBACK VERIFICATION BOOT (WP17 #9..#19 NOT applied) ==="
cd $K && bash run.sh 300 > /dev/null 2>&1 || true
cp -f serial.log ./work/phaseA_serial.log

echo "=== [9] the rollback gate (grep ... || exit 1) ==="
grep -a -m1 "SIE CONFIDENTIAL" serial.log        || { echo "!! banner missing — REGRESSION"; exit 1; }
grep -a -m1 "Memory mode" serial.log             || { echo "!! Memory mode missing — REGRESSION"; exit 1; }
grep -a -m1 "Preloaded elf kernel" serial.log    || { echo "!! Preloaded elf kernel missing — REGRESSION"; exit 1; }
grep -a -m1 "CPU: AMD EPYC" serial.log           || { echo "!! CPU ID missing — REGRESSION"; exit 1; }
grep -a -m1 "CPU Features" serial.log            || { echo "!! CPU Features missing — REGRESSION"; exit 1; }
grep -a -m1 'Event timer "LAPIC"' serial.log     || { echo "!! Event timer missing — REGRESSION"; exit 1; }
grep -a -m1 "ACPI APIC Table" serial.log         || { echo "!! ACPI table missing — REGRESSION"; exit 1; }
grep -a -m1 "Multiprocessor System" serial.log   || { echo "!! SMP missing — REGRESSION"; exit 1; }
grep -a -m1 "APIC: CPU 0 has ACPI ID 0" serial.log || { echo "!! APIC CPU0 missing — REGRESSION"; exit 1; }
echo ">>> ROLLBACK OK — all WP16-era boot lines are back <<<"

echo "=== [10] the new frontier ==="
grep -a -m1 "fault virtual address" serial.log || true
grep -a -m1 "instruction pointer" serial.log || echo "(no crash — clean boot!)"
grep -a -m1 "panic:" serial.log || true
grep -a -c "can't re-use a leaf" serial.log | xargs echo "sysctl leaf lines:"
wc -l serial.log | xargs echo "serial lines:"
echo "=== WP18 Phase A complete ==="
