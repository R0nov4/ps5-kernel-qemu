#!/bin/bash
# ============================================================================
# WP18 — ROLLBACK + the local-guard continuation (dev rebuild)
# WP16 chain (full rebuild from pristine) + WP17 #1..#8 ONLY (the
#   zone/malloc/window family that fixed 0x9e82b788 + td_locks -1)
#   + WP18 local guards (NO .data seeds, NO allocator-path changes):
#       #2  cpuset-zone bootstrap NULL-skip      (slot 0x9E401C80)
#       #3  cpuset-root refcount NULL skip       (slot 0x9E401D80)
#       #4  zone-create NULL-return guard        (slot 0x9E401E00)
#       #5  fork zone-alloc ENOMEM error return  (slot 0x9E401E80)
#       #6  audit_worker kproc tolerance         (slot 0x9E401F00)
#       #7  create_init fork tolerance           (slot 0x9E401F80)
#       #8  idle_setup loop kproc tolerance      (slot 0x9E402000)
#       #9  idle_setup FIRST kproc tolerance     (slot 0x9E402080)
#       #10 cpurv_init kproc tolerance x2        (slots 0x9E402100/180)
#       #11 zone-stats accessor NULL-zone guard  (slot 0x9E402200)
# ============================================================================
set -e
set -o pipefail
cd .
S=./scripts
K=./kit_build

echo "=== [0] WP16 chain (full rebuild from pristine f242f55e) ==="
bash $S/wp16_build_all.sh | tail -3

echo "=== [1] WP17 #1/#2/#3 zone-drain guard (cave63/64 + zone-table seed) ==="
python3 -u $S/wp17_patch_zonedrain_guard.py | tail -1
echo "=== [2] WP17 #4 kmem thunk read-time fallback (cave65) ==="
python3 -u $S/wp17_patch_kmem_thunk.py | tail -1
echo "=== [3] WP17 #5 W1 v3 vm_page supply extension (cave66) ==="
python3 -u $S/wp17_patch_w1_extend.py | tail -1
echo "=== [4] WP17 #6 malloc bump window 380KB -> 5.6MB (caves 50/56/51) ==="
python3 -u $S/wp17_patch_malloc_window.py | tail -1
echo "=== [5] WP17 #7 cave57 exit retarget (td_locks double-unlock) ==="
python3 -u $S/wp17_patch_cave57_retarget.py | tail -1
echo "=== [6] WP17 #8 kmem-arena lazy bootstrap (cave67) ==="
python3 -u $S/wp17_patch_kmem_arena_boot.py | tail -1

echo "=== [6b] WP18 #1 OID path-walker loop-head guard (cave68 — re-applied, a pure local guard) ==="
python3 -u $S/wp17_patch_oidwalk_guard.py | tail -1

echo "=== [7] WP18 #2 cpuset-zone bootstrap NULL-skip ==="
python3 -u $S/wp18_patch_cpuset_init.py | tail -1
echo "=== [8] WP18 #3 cpuset-root refcount NULL skip ==="
python3 -u $S/wp18_patch_cpuroot_ref.py | tail -1
echo "=== [9] WP18 #4 zone-create NULL-return guard ==="
python3 -u $S/wp18_patch_zonecreate_null.py | tail -1
echo "=== [10] WP18 #5 fork zone-alloc ENOMEM error return ==="
python3 -u $S/wp18_patch_fork_alloc.py | tail -1
echo "=== [11] WP18 #6 audit_worker kproc tolerance ==="
python3 -u $S/wp18_patch_audit_kproc.py | tail -1
echo "=== [12] WP18 #7 create_init fork tolerance ==="
python3 -u $S/wp18_patch_init_fork.py | tail -1
echo "=== [13] WP18 #8 idle_setup loop kproc tolerance ==="
python3 -u $S/wp18_patch_idle_kproc.py | tail -1
echo "=== [14] WP18 #9 idle_setup FIRST kproc tolerance ==="
python3 -u $S/wp18_patch_idle2_kproc.py | tail -1
echo "=== [15] WP18 #10 cpurv_init kproc tolerance x2 ==="
python3 -u $S/wp18_patch_cpurv_kproc.py | tail -1
echo "=== [16] WP18 #11 zone-stats accessor NULL-zone guard ==="
python3 -u $S/wp18_patch_zonestats_guard.py | tail -1

echo "=== [17] size sanity (must equal pristine 65224704) ==="
SZ=$(stat -c%s $K/wp3_boot/kernel_raw.bin)
echo "kernel_raw.bin size: $SZ"
[ "$SZ" = "65224704" ] || { echo "!! SIZE MISMATCH — aborting"; exit 1; }

echo "=== [18] frontier boot ==="
cd $K && bash run.sh 300 > /dev/null 2>&1 || true
grep -a -m1 "fault virtual address" serial.log || true
grep -a -m1 "instruction pointer" serial.log || echo "(no crash — clean boot!)"
grep -a -m1 "panic:" serial.log || true
grep -a -c "can't re-use a leaf" serial.log | xargs echo "sysctl leaf lines:"
wc -l serial.log | xargs echo "serial lines:"
echo "=== WP18 rebuild complete ==="
