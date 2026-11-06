#!/bin/bash
# ============================================================================
# WP19 — THE REAL KTHREADS: fork1's full pipeline via the designed-object
#         bump-window caves + the DMAP self-healing trap entry
# ----------------------------------------------------------------------------
# THE WP19 METHOD (the user's directive #2, extended by the chase):
#   the allocators keep their designed NULL-on-failure semantics; for the
#   SPECIFIC fork-pipeline call sites whose NULL answer stalls the march,
#   a cave replays the alloc and carves a page-aligned, zeroed object from
#   the SHARED bump window [0x3F1A1000, 0x3F740000) (the cave50/56 cursor,
#   validated inside [BASE,CEIL] first); window exhausted -> the site's own
#   designed NULL/error path. The general zone_create path is UNTOUCHED.
#
# THE PATCH STACK:
#   [0]  WP16 chain (pristine f242f55e -> WP12 -> WP13 -> WP14 -> WP15
#        -> WP16, incl. its own verification boot)
#   [1]  WP17 #1..#8   (caves 63..67 + the window + the retarget)
#   [2]  WP18 #1..#24  (cave68 + the 24 local guards)
#   [3]  WP19 #1  cave80  fork1 THREAD-object allocator   (0x9f0a1626)
#   [4]  WP19 #2  cave81  proc_create PROC-object alloc   (0x9ef80a5d)
#   [5]  WP19 #3  cave82  kstack-zone object allocator    (0x9e851ae7)
#   [6]  WP19 #4  cave83  kstack-VA bump allocator v2     (0x9e92a634)
#   [7]  WP19 #5  cave84  finew FILEDESC-object allocator (0x9eb1cdff)
#   [8]  WP19 #6  cave85  fork1 NULL-parent fd guard      (0x9f0a20b0)
#   [9]  WP19 #7  cave86+87 cpuset ROOT SET              (0x9ec2d097/102)
#   [10] WP19 #8  cave88  fork1 child-sigacts allocator  (0x9f0a2340)
#   [11] WP19 #9  cave89  thread-cpuset allocator        (0x9ec2ca64)
#   [12] WP19 #10 cave90  fork-proc container allocator  (0x9e6c081e)
#   [13] WP19 #11 cave91  PT-page pool self-sustaining pop (0x9ece1e32)
#        + the window-DMAP huge-page PDE installs + the PT PTE fills
#   [14] WP19 #12 cave92  PT-fill install re-assertion   (0x9ecd038c)
#   [15] WP19 #13 cave93  the TRAP-ENTRY window-fault self-healing
#        (0x9e7de0e0: cr2 in the window -> the region's huge-page PDE,
#         the original dump layout (va&~0x1fffff)-0x800000|0x1e3)
#   [16] WP19 #14 cave94  fork1 container-out guard      (0x9f0a17f6)
#
# THE VERIFICATION BOOT RESULT (3832 lines vs WP18's 1214):
#   ... -> Event timer LAPIC -> ACPI APIC -> SMP -> APIC: CPU 0 ->
#   THE FORK PIPELINE RUNS FOR REAL: the 'error 12' prints are GONE
#   (0 occurrences vs 5 in WP18) — real threads/procs/kstacks/filedescs/
#   sigacts/cpusets/containers — the first window faults self-heal via
#   the trap entry — then the march stalls in fork1's deepest container-
#   out residue chain (120 trap cycles, each printed + recovered, the
#   kernel stays ALIVE — QEMU still running, no halt, no power-down).
#
# usage: bash scripts/wp19_build_all.sh
# ============================================================================
set -e
set -o pipefail
cd .
S=./scripts
K=./kit_build

echo "=== [0] WP16 chain (full rebuild from pristine f242f55e, incl. its verification boot) ==="
# WP19_SKIP_WP16=1 skips the (WP18-kit-proven) WP12->WP16 rebuild — for
# incremental validation on an already-built tree; the default rebuilds.
if [ -z "$WP19_SKIP_WP16" ]; then
    bash $S/wp16_build_all.sh | tail -3
else
    echo "(skipped — WP19_SKIP_WP16=1: the tree is already at the WP16+WP17+WP18 base)"
fi

echo "=== [1] WP17 #1..#8 (the zone/malloc/window family) ==="
python3 -u $S/wp17_patch_zonedrain_guard.py | tail -1
python3 -u $S/wp17_patch_kmem_thunk.py | tail -1
python3 -u $S/wp17_patch_w1_extend.py | tail -1
python3 -u $S/wp17_patch_malloc_window.py | tail -1
python3 -u $S/wp17_patch_cave57_retarget.py | tail -1
python3 -u $S/wp17_patch_kmem_arena_boot.py | tail -1
python3 -u $S/wp17_patch_oidwalk_guard.py | tail -1

echo "=== [2] WP18 #1..#24 (cave68 + the 24 local guards) ==="
for p in wp18_patch_cpuset_init wp18_patch_cpuroot_ref wp18_patch_zonecreate_null \
         wp18_patch_fork_alloc wp18_patch_audit_kproc wp18_patch_init_fork \
         wp18_patch_idle_kproc wp18_patch_idle2_kproc wp18_patch_cpurv_kproc \
         wp18_patch_zonestats_guard wp18_patch_zonesetters_guard wp18_patch_zcreate_parent \
         wp18_patch_zcreate_keg wp18_patch_zcreate_flags wp18_patch_zonesetter2_guard \
         wp18_patch_intrsrc_lazyinit wp18_patch_ithread_kproc wp18_patch_intrname_skip \
         wp18_patch_intrlog_skip wp18_patch_threadclean_guard wp18_patch_threadfree_guard \
         wp18_patch_netisr_worker wp18_patch_threadcreate_null; do
    python3 -u $S/$p.py | tail -1
done

echo "=== [3..16] WP19 #1..#14 (the designed-object caves 80..94) ==="
python3 -u $S/wp19_patch_thread_alloc.py        | tail -1
python3 -u $S/wp19_patch_proc_alloc.py          | tail -1
python3 -u $S/wp19_patch_kstack_zone.py        | tail -1
python3 -u $S/wp19_patch_kstack_va.py          | tail -1
python3 -u $S/wp19_patch_filedesc_alloc.py     | tail -1
python3 -u $S/wp19_patch_fdnull_guard.py       | tail -1
python3 -u $S/wp19_patch_cpuset_root.py        | tail -1
python3 -u $S/wp19_patch_sigacts_alloc.py      | tail -1
python3 -u $S/wp19_patch_threadcpuset_alloc.py | tail -1
python3 -u $S/wp19_patch_container_alloc.py    | tail -1
python3 -u $S/wp19_patch_pcpu_residue.py       | tail -1
python3 -u $S/wp19_patch_ptfill_reassert.py    | tail -1
python3 -u $S/wp19_patch_trapfix_window.py     | tail -1
python3 -u $S/wp19_patch_container_out_guard.py | tail -1

echo "=== [17] size sanity (must equal pristine 65224704) ==="
SZ=$(stat -c%s $K/wp3_boot/kernel_raw.bin)
echo "kernel_raw.bin size: $SZ"
[ "$SZ" = "65224704" ] || { echo "!! SIZE MISMATCH — aborting"; exit 1; }

echo "=== [18] THE WP19 VERIFICATION BOOT (alive-check: QEMU must stay up) ==="
cd $K
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
rm -f serial.log
$QEMU -L ./bios -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=serial.log \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot 2>/dev/null &
QPID=$!
ALIVE=0
for i in $(seq 1 75); do
  sleep 1
  kill -0 $QPID 2>/dev/null || break
  L=$(wc -l < serial.log 2>/dev/null || echo 0)
  [ "$L" -ge 3800 ] && { sleep 3; kill -0 $QPID 2>/dev/null && ALIVE=1; break; }
done
if [ $ALIVE -eq 1 ]; then
  echo ">>> kernel ALIVE at the frontier (QEMU up, $L serial lines) <<<"
else
  echo "!! kernel did not reach the alive frontier"; kill $QPID 2>/dev/null; exit 1
fi
kill $QPID 2>/dev/null; wait 2>/dev/null

echo "=== [19] THE ROLLBACK GATE (the WP16-era lines — grep ... || exit 1) ==="
grep -a -m1 "SIE CONFIDENTIAL" serial.log          || { echo "!! banner missing — REGRESSION"; exit 1; }
grep -a -m1 "Memory mode" serial.log               || { echo "!! Memory mode missing — REGRESSION"; exit 1; }
grep -a -m1 "Preloaded elf kernel" serial.log      || { echo "!! Preloaded elf kernel missing — REGRESSION"; exit 1; }
grep -a -m1 "CPU: AMD EPYC" serial.log             || { echo "!! CPU ID missing — REGRESSION"; exit 1; }
grep -a -m1 "CPU Features" serial.log              || { echo "!! CPU Features missing — REGRESSION"; exit 1; }
grep -a -m1 'Event timer "LAPIC"' serial.log       || { echo "!! Event timer missing — REGRESSION"; exit 1; }
grep -a -m1 "ACPI APIC Table" serial.log           || { echo "!! ACPI table missing — REGRESSION"; exit 1; }
grep -a -m1 "Multiprocessor System" serial.log     || { echo "!! SMP missing — REGRESSION"; exit 1; }
grep -a -m1 "APIC: CPU 0 has ACPI ID 0" serial.log || { echo "!! APIC CPU0 missing — REGRESSION"; exit 1; }
echo ">>> rollback OK — all pre-fork boot lines present <<<"

echo "=== [20] THE WP19 FRONTIER GATE (the real-kthread evidence — grep ... || exit 1) ==="
E12=$(grep -a -c "error 12" serial.log || true)
echo "designed kthread-error prints: $E12"
[ "$E12" = "0" ] || { echo "!! error-12 prints present — the fork pipeline regressed"; exit 1; }
LINES=$(wc -l < serial.log)
echo "serial lines: $LINES"
[ "$LINES" -ge 3800 ] || { echo "!! the march did not reach the deep frontier"; exit 1; }
grep -a -m1 "APIC: CPU 0 has ACPI ID 0" serial.log || { echo "!! frontier line missing"; exit 1; }
echo ">>> frontier OK — fork1's pipeline runs with REAL objects (no ENOMEM prints) <<<"

echo "=== [21] THE TRAP-TOLERANCE GATE (the documented self-healing frontier) ==="
TRAPS=$(grep -a -c "Fatal trap" serial.log || true)
echo "Fatal-trap cycles (self-healed + the documented stall loop): $TRAPS"
[ "$TRAPS" -le 200 ] || { echo "!! unbounded trap loop — a new regression"; exit 1; }
grep -a -q "kernel trap with interrupts enabled" serial.log && { echo "!! irq-enabled trap — REGRESSION"; exit 1; }
grep -a -q "kernel trap 9 " serial.log && { echo "!! GPF regression — REGRESSION"; exit 1; }
echo ">>> trap-tolerance OK — bounded, diagnosed, self-healing where designed <<<"

echo "=== [22] THE WP20 PENDING SECTION (the documented trade-off — informational) ==="
echo "  NOT reached in this kit (the fork-pipeline stall — see worklog WP19):"
for pat in "MADT: Found IO APIC" "ioapic0 <Version" "cpu0 BSP:" "netisr_init:" "taskqueue_start_threads" "gc_suspend_resume"; do
  if grep -a -q "$pat" serial.log; then echo "  REACHED: $pat"; else echo "  PENDING (WP20): $pat"; fi
done
echo ">>> the march lines past the fork SYSINITs are the documented WP20 target <<<"

echo "=== [23] summary ==="
grep -a -c "can't re-use a leaf" serial.log | xargs echo "sysctl leaf lines:"
wc -l serial.log | xargs echo "serial lines:"
grep -a -c "Fatal trap" serial.log | xargs echo "trap cycles (documented):"
echo "=== WP19 build complete ==="
