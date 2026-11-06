#!/bin/bash
# ============================================================================
# WP16 — full reproducible build of the PS5 13.60 boot kit
# pristine WP7 base -> WP12 chain -> WP13 chain -> WP14 chain (no boot)
#   + WP15 (19 fixes, no boot)
#   + WP16 (20 fixes):
#       #1  cpu_switch no-op guard + sched-lock undo (cave43 @0x9E400E80)
#           crash: Fatal double fault rip=0x9e642348 rsp=0x0 — the
#           pcb-less fake idle thread's zero context load. thread0
#           (mid-SYSINIT, wmesg 'vmwait') now returns cleanly.
#       #2  gs:[8] (pc_idlethread) reseed -> thread0 (image + cave33/36)
#           choosethread's empty-runq answer == curthread -> mi_switch's
#           DESIGNED same-thread path (no cpu_switch call at all).
#       #3  one-shot 8259 PIC mask at critical_exit (cave44 @0x9E400F00)
#           'Servicing hardware INT=0x08' — the unremapped PIT IRQ0 hit
#           IDT[8] at the FIRST interrupt-enable -> false 'double fault'.
#       #4  vm_page_alloc second-chance NULL guard (cave45 @0x9E400F80)
#           crash 0x9ef7a475 CR2=0x50: the W1-bump exhaustion (3823
#           objects = 14.9MB) -> the designed NULL return -> the fill
#           loop's designed shortage handling.
#       #5  vm_reserv walk early-exit (cave46 @0x9E401000)
#           'panic: _rw_wunlock_cookie: td_locks -32768' — the 64K-iter
#           runaway with the unbalanced per-iteration unlock; the walk
#           now ends at the first NULL with the counter restored.
#       #6  region-manager bump allocator (cave47 @0x9E401080)
#           'panic: kmem_suballoc: bad status return of 3' — the
#           zero-page region manager hands out the fresh kernel-VA
#           window [0xffffffffa4000000, 0xffffffffa8000000).
#       #7  region-mgr constructor object bump (cave48 @0x9E401100)
#           crash 0x9e6b6ef1 CR2=0x0: the WP13 'malloc->NULL' family —
#           the sub-manager constructor's object from the 64KB gap.
#       #8  region-mgr insert skip for the zero manager (cave49 @0x9E401180)
#           crash 0x9e6bb4cc CR2=0x28: the tree-walk on the NULL-rooted
#           extent tree — the decorative tree in our reconstruction.
#       #9  pbuf/bufwait list cold start (image .data wipe)
#           crash 0x9e84d990 CR2=0xffffff8006e496d8: the 0xffffff80
#           live-residue list head -> the designed empty-list path.
#       #10 systemic malloc bump at the NULL node (cave50 @0x9E401200)
#           crash 0x9e9471ad CR2=0x8: every malloc failure (the NULL
#           zone-table family, the large-alloc fail) gets real memory
#           from [0x3F1A1000, 0x3F200000) — the sysctl-leaf + preload
#           + eventtimer/LAPIC + ACPI + SMP stages now run.
#       #11 free() no-op for bump-window objects (cave51 @0x9E401280)
#           'panic: free: address ... has not been allocated' — the bump
#           objects leak instead of panicking.
#       #12 OID tree walk NULL-terminator guard (cave52 @0x9E401300)
#           crash 0x9eef4158 CR2=0x18: the wiped static OID links.
#       #13 OID walk family guards (caves 53/54/55)
#           crash 0x9eef424c CR2=0x18: the sibling instances.
#       #14 zone chunk-import page bump (cave56 @0x9E401500)
#           crash 0x9e82b298 CR2=0xb0: the NULL import slot.
#       #15 kmem-arena extend-thunk bootstrap (cave57 @0x9E401580)
#           'panic: failed to allocate waiting allocation' — the dynamic
#           kmem arena gets the WP14 thunk -> the shared 14MB pool.
#       #16 region-manager global redirect (cave58 @0x9E401600)
#           crash 0x9e81dd69 CR2=0x20: the garbage-map manager ->
#           the guarded zero-page manager.
#       #17 lock-stats helper NULL guard (cave59 @0x9E401680)
#           crash 0x9e81dd69: the NULL lock-domain table.
#       #18 witness chain NULL guard (cave60 @0x9E401700)
#           crash 0x9e81dee3 CR2=0x40.
#       #19 witness unlock NULL guard (cave61 @0x9E401780)
#           crash 0x9e81df3d CR2=0x80.
#       #20 mtx unlock NULL-lock no-op (cave62 @0x9E401800)
#           crash 0x9e8b753e CR2=0x8.
# usage: bash scripts/wp16_build_all.sh
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

echo "=== [20] WP16 #1 cpu_switch no-op guard + sched-lock undo (cave43) ==="
python3 -u $S/wp16_patch_ctxswitch_noop.py | tail -2
echo "=== [21] WP16 #2 gs:[8] idlethread -> thread0 ==="
python3 -u $S/wp16_patch_idle_thread0.py | tail -2
echo "=== [22] WP16 #3 one-shot PIC mask at critical_exit (cave44) ==="
python3 -u $S/wp16_patch_picmask.py | tail -2
echo "=== [23] WP16 #4 vm_page_alloc NULL guard (cave45) ==="
python3 -u $S/wp16_patch_vmpagealloc_null.py | tail -2
echo "=== [24] WP16 #5 vm_reserv walk early-exit (cave46) ==="
python3 -u $S/wp16_patch_reservwalk_exit.py | tail -2
echo "=== [25] WP16 #6 region-manager bump allocator (cave47) ==="
python3 -u $S/wp16_patch_regionmgr_bump.py | tail -2
echo "=== [26] WP16 #7 region-mgr constructor object bump (cave48) ==="
python3 -u $S/wp16_patch_regionmgr_ctor.py | tail -2
echo "=== [27] WP16 #8 region-mgr insert skip (cave49) ==="
python3 -u $S/wp16_patch_regionmgr_insert.py | tail -2
echo "=== [28] WP16 #9 pbuf/bufwait list cold start ==="
python3 -u $S/wp16_patch_pbuf_coldstart.py | tail -2
echo "=== [29] WP16 #10 systemic malloc bump (cave50) ==="
python3 -u $S/wp16_patch_malloc_bump.py | tail -2
echo "=== [30] WP16 #11 free() no-op for bump objects (cave51) ==="
python3 -u $S/wp16_patch_free_noop.py | tail -2
echo "=== [31] WP16 #12 OID tree walk NULL guard (cave52) ==="
python3 -u $S/wp16_patch_oidwalk_guard.py | tail -2
echo "=== [32] WP16 #13 OID walk family guards (caves 53/54/55) ==="
python3 -u $S/wp16_patch_oidwalk2_guard.py | tail -2
echo "=== [33] WP16 #14 zone chunk-import page bump (cave56) ==="
python3 -u $S/wp16_patch_zoneimport_bump.py | tail -2
echo "=== [34] WP16 #15 kmem-arena extend-thunk bootstrap (cave57) ==="
python3 -u $S/wp16_patch_kmem_arena_thunk.py | tail -2
echo "=== [35] WP16 #16 region-manager global redirect (cave58) ==="
python3 -u $S/wp16_patch_regmgr_global.py | tail -2
echo "=== [36] WP16 #17 lock-stats helper NULL guard (cave59) ==="
python3 -u $S/wp16_patch_lockstats_guard.py | tail -2
echo "=== [37] WP16 #18 witness chain NULL guard (cave60) ==="
python3 -u $S/wp16_patch_witness_guard.py | tail -2
echo "=== [38] WP16 #19 witness unlock NULL guard (cave61) ==="
python3 -u $S/wp16_patch_witness_unlock.py | tail -2
echo "=== [39] WP16 #20 mtx unlock NULL no-op (cave62) ==="
python3 -u $S/wp16_patch_mtxunlock_noop.py | tail -2

echo "=== [40] size sanity (must equal pristine 65224704) ==="
SZ=$(stat -c%s $K/wp3_boot/kernel_raw.bin)
echo "kernel_raw.bin size: $SZ"
[ "$SZ" = "65224704" ] || { echo "!! SIZE MISMATCH — aborting"; exit 1; }

echo "=== [41] verification boot ==="
cd $K && bash run.sh 300 > /dev/null 2>&1 || true
grep -a -m1 "SIE CONFIDENTIAL" serial.log || echo "!! banner missing"
grep -a -m1 "Memory mode" serial.log || echo "!! Memory mode missing"
grep -a -c "can't re-use a leaf" serial.log | xargs echo "sysctl leaf lines:"
grep -a -m1 "Preloaded elf kernel" serial.log || echo "!! Preloaded elf missing"
grep -a -m1 "Event timer" serial.log || echo "!! Event timer missing"
grep -a -m1 "ACPI APIC Table" serial.log || echo "!! ACPI table missing"
grep -a -m1 "Multiprocessor System" serial.log || echo "!! SMP missing"
grep -a -m1 "CPU Features" serial.log || echo "!! CPU Features missing"
grep -a -m1 "panic:" serial.log || true
grep -a -m1 "instruction pointer" serial.log || echo "(no crash — clean boot!)"
wc -l serial.log | xargs echo "serial lines:"
echo "=== WP16 build complete ==="
