#!/bin/bash
# ============================================================================
# WP15 — full reproducible build of the PS5 13.60 boot kit
# pristine WP7 base -> WP12 chain (no boot) -> WP13 chain (no boot)
#   -> WP14 chain (no boot)
#   + WP15:
#       #1  pmap_enter pv-list TAILQ lazy-init (cave24 @0x9E400500)
#           crash 0x9ecd2d0c CR2=0x0 WRITE — the vm_page array lives on
#           raw zero pages: md.pv_list {tqh_first@+0x38, tqh_last@+0x40}
#           lacks the TAILQ_INIT self-anchor -> first pv insert writes
#           *NULL. Lazy-init: tqh_last==0 -> rcx = &tqh_first.
#       #2  vm_dom block-array NULL guards (caves 25/26/27) — crash
#           0x9e945c1f CR2=0x38: [vm_dom[i]+0x10] (2MB-block descriptor
#           array) NULL for every domain -> the "block full/empty" and
#           "take page from block" checkers fault. NULL -> the exact
#           zero-array answers (-1/-1/empty-exit).
#       #3  W1 bump step 0x78 -> 0xF0 + exhaustion bound — the plinks.q
#           queue-corruption panic (assert 0x9ef7c2fb): the W1 objects'
#           +0x78 field landed on the NEXT vm_page's +0x00 (the vm_page
#           needs >= 0x80; GDB: W1#1+0x78 == W1#2 == the corrupted m1).
#           Note: the vm_page ARRAY stride is 0x78 (0x9ea05623 imul) —
#           the extra margin covers unobserved fields.
#       #4  vm_page_dequeue never-enqueued guard (cave28 @0x9E400780) —
#           crash 0x9ef7c269 CR2=0x0: the alloc path dequeues the fresh
#           W1 page (links 0/0 — never in any page queue). prev==0 ->
#           plain ret (no lock taken yet; the epilogue tail-jmps to the
#           unlock so the early exit must not unlock).
#       #5  vm_dom block-array SEED — [vm_dom[i]+0x10] := DMAP(0x3F170000)
#           for i=0..10 (systemic root fix; subsumes #2; 128KB zero
#           region covers 1024 blocks). Fixed crash 0x9e945629 CR2=0x9da0
#           (block 504 = the seed area itself).
#       #6  dom0 free-area bucket array seed — [bucket_i+0x10] :=
#           DMAP(0x23000000) for the 8 dom0 buckets @0xa1add9a0: the
#           WP12-wiped vm_page-array pointers + WP13's malloc->NULL left
#           them zero; the lookup (0x9ea055b0, stride 0x78) dereferenced
#           NULL+25345*0x78+0x68 (crash 0x9ea05663 CR2=0x2e68e0). The
#           seed region [0x23000000,0x23800000) lies in the bucket2/3
#           hole (never page-ified, stays zero, 8MB coverage).
#       #7  bucket-list remove never-linked guard (cave30 @0x9E400800) —
#           crash 0x9ea05bfe CR2=0x0: the zero-seeded lookup "finds" the
#           all-zero fake vm_page and removes it from the bucket object
#           list; prev==0 -> jump to the designed tail (mov byte
#           [rsi+0x68], 0xb = "bucket none"), skipping the unlink and
#           the count decrement.
# usage: bash scripts/wp15_build_all.sh
# ============================================================================
set -e
set -o pipefail
cd .
S=./scripts
K=./kit_build

echo "=== [0] WP14 chain (WP7 base + WP9 + MADT + WP11 + WP12 + WP13 + WP14), no boot ==="
WP14_NOBOOT=1 bash $S/wp14_build_all.sh "$@" | tail -3

echo "=== [1] WP15 #1 pmap_enter pv-list TAILQ lazy-init ==="
python3 -u $S/wp15_patch_tailq_lazyinit.py | tail -2

echo "=== [2] WP15 #2 vm_dom checker NULL guards ==="
python3 -u $S/wp15_patch_domnull.py | tail -2

echo "=== [3] WP15 #3 W1 bump step 0xF0 + exhaustion bound ==="
python3 -u $S/wp15_patch_w1step.py | tail -2

echo "=== [4] WP15 #4 vm_page_dequeue never-enqueued guard ==="
python3 -u $S/wp15_patch_dequeue_guard.py | tail -2

echo "=== [5] WP15 #5 vm_dom block-array seed ==="
python3 -u $S/wp15_patch_domseed.py | tail -2

echo "=== [6] WP15 #6 dom0 bucket array seed ==="
python3 -u $S/wp15_patch_bucketseed.py | tail -2

echo "=== [7] WP15 #7 bucket-list remove never-linked guard ==="
python3 -u $S/wp15_patch_bucketrm_guard.py | tail -2

echo "=== [8] WP15 #8 sleepq wakeup NULL-sq guard ==="
python3 -u $S/wp15_patch_sleepqwake_guard.py | tail -2

echo "=== [9] WP15 #9 callout hash-table seed ==="
python3 -u $S/wp15_patch_calloutseed.py | tail -2

echo "=== [10] WP15 #10 mtx acquire word==0 fast-path ==="
python3 -u $S/wp15_patch_mtxzero.py | tail -2

echo "=== [11] WP15 #11 pcpu gs:[8] NULL guard ==="
python3 -u $S/wp15_patch_pcpuguard.py | tail -2

echo "=== [12] WP15 #12 AP-state loop NULL-object exit guard ==="
python3 -u $S/wp15_patch_aploop_guard.py | tail -2

echo "=== [13] WP15 #13 atomic-swap helper NULL-target guard ==="
python3 -u $S/wp15_patch_swapnull_guard.py | tail -2

echo "=== [14] WP15 #14 pcpu gs:[8] image seed ==="
python3 -u $S/wp15_patch_pcpuseed.py | tail -2

echo "=== [15] WP15 #15 gs:[8] runtime seed fallback ==="
python3 -u $S/wp15_patch_gs8fallback.py | tail -2

echo "=== [16] WP15 #16 swap-helper NULL-old guard ==="
python3 -u $S/wp15_patch_swapold_guard.py | tail -2

echo "=== [17] WP15 #17 pmap-activate NULL-proc guard ==="
python3 -u $S/wp15_patch_activate_guard.py | tail -2

echo "=== [18] WP15 #18 idle-loop NULL-proc guard ==="
python3 -u $S/wp15_patch_idleproc_guard.py | tail -2

echo "=== [19] WP15 #19 context-switch NULL-pcb cluster ==="
python3 -u $S/wp15_patch_ctxswitch.py | tail -2

echo "=== [8] size sanity (must equal pristine 65224704) ==="
SZ=$(stat -c%s $K/wp3_boot/kernel_raw.bin)
echo "kernel_raw.bin size: $SZ"
[ "$SZ" = "65224704" ] || { echo "!! SIZE MISMATCH — aborting"; exit 1; }

echo "=== [9] verification boot ==="
cd $K && bash run.sh 300 > /dev/null 2>&1 || true
grep -a -m1 "SIE CONFIDENTIAL" serial.log || echo "!! banner missing"
grep -a -m1 "Memory mode" serial.log || echo "!! Memory mode missing"
grep -a -c "can't re-use a leaf" serial.log | xargs echo "sysctl leaf lines:"
grep -a -m1 "CPU Features" serial.log || echo "!! CPU Features missing"
grep -a -m1 "instruction pointer" serial.log || echo "(no crash — clean boot!)"
grep -a -m1 "panic:" serial.log || true
wc -l serial.log | xargs echo "serial lines:"
echo "=== WP15 build complete ==="
