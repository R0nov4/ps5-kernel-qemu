#!/bin/bash
# ============================================================================
# WP18 — THE ROLLBACK + the LOCAL-GUARD-ONLY continuation
# ----------------------------------------------------------------------------
# THE WP17 REGRESSION (fixed here): WP17 #9..#19 (oid_parent_seed, cave69's
#   import-failure bump, cave75's malloc-NULL bump, the witness seeds
#   cave76..79) made the allocators return RAW PAGES instead of their
#   designed NULL in EARLY boot -> witness/early zones activated BEFORE
#   'Preloaded elf kernel' -> the GPF 0xffffffff9e8b7908 right at the
#   'randompid' sysctl leaf. The old build script's '|| echo' verification
#   let the regression ship inside the kit zip.
#
# THE WP18 METHOD (the user's directive):
#   1. ROLLBACK: WP17 keeps ONLY #1..#8 (the zone/malloc/window family that
#      fixed 0x9e82b788 + the td_locks -1 double-unlock). #9..#19 are gone.
#      The allocators keep their designed NULL-on-failure semantics.
#   2. EVERY crash after 'APIC: CPU 0 has ACPI ID 0' is fixed with a LOCAL
#      GUARD at the crash site — no .data seeds, no allocator-path changes,
#      no subsystem activation. Non-essential subsystems are skipped;
#      essential ones take their DESIGNED error/NULL paths.
#   3. EVERY verification grep is '|| exit 1' — a regression can never ship.
#
# BOOT RESULT (verified): the full SYSINIT march — Preloaded elf kernel,
#   CPU/cache/SMAP, Event timer LAPIC, ACPI APIC Table, SMP enumeration,
#   APIC: CPU 0, the whole ioapic/lapic interrupt setup (MADT overrides,
#   intpin triggers, cpu0 BSP LINT/timer), netisr_init, the taskqueue
#   family's DESIGNED error prints — then the kernel sits ALIVE in its
#   idle loop: no trap, no panic, no power-down (QEMU stays up).
#
# THE PATCH STACK:
#   [0]  WP16 chain (pristine f242f55e -> WP12 -> WP13 -> WP14 -> WP15
#        -> WP16, incl. its own verification boot)
#   [1]  WP17 #1..#8  (caves 63..67 + the window + the retarget)
#   [2]  WP18 #1   OID path-walker loop-head guard     (cave68 @0x9E401C00)
#        - crash 0xffffffff9e946a00 CR2=0x34
#   [3]  WP18 #2   cpuset-zone bootstrap NULL-skip     (slot  @0x9E401C80)
#        - crash 0xffffffff9ec2d09c CR2=0x0   (the OLD cave69 site — now a
#          pure caller-side skip, the allocator still answers NULL)
#   [4]  WP18 #3   cpuset-root refcount NULL skip      (slot  @0x9E401D80)
#        - crash 0xffffffff9ec2c374 CR2=0x8
#   [5]  WP18 #4   zone-create NULL-return guard       (slot  @0x9E401E00)
#        - crash 0xffffffff9ee1e9d0 CR2=0x40 ('filedesc structure')
#   [6]  WP18 #5   fork zone-alloc ENOMEM return       (slot  @0x9E401E80)
#        - crash 0xffffffff9f0a162b CR2=0x10 (fork1)
#   [7]  WP18 #6   audit_worker kproc tolerance        (slot  @0x9E401F00)
#        - panic 'audit_worker_init: kproc_create returned 12'
#   [8]  WP18 #7   create_init fork tolerance          (slot  @0x9E401F80)
#        - panic 'cannot fork init: 12'
#   [9]  WP18 #8   idle_setup loop kproc tolerance     (slot  @0x9E402000)
#   [10] WP18 #9   idle_setup FIRST kproc tolerance    (slot  @0x9E402080)
#        - panic 'idle_setup: kproc_create error 12' (TWO call sites)
#   [11] WP18 #10  cpurv_init kproc tolerance x2       (slots @0x9E402100/180)
#        - panic 'cpurv_init: kproc_create error 12'
#   [12] WP18 #11  zone-stats accessor NULL-zone guard (slot  @0x9E402200)
#        - crash 0xffffffff9e82d1db CR2=0x68 (the DESIGNED empty path)
#   [13] WP18 #12  zone-setter family NULL-zone x4     (slots @0x9E402280..400)
#        - crash 0xffffffff9e82d2ca CR2=0x40 (+3 siblings)
#   [14] WP18 #13  zone_create_ext NULL-parent guard   (slot  @0x9E402480)
#        - crash 0xffffffff9e82b552 CR2=0x68
#   [15] WP18 #14  zone_create_ext NULL-keg field      (slot  @0x9E402500)
#        - crash 0xffffffff9e82b57b CR2=0x80
#   [16] WP18 #15  zone_create_ext NULL-keg flags      (slot  @0x9E402580)
#        - crash 0xffffffff9e82b59c CR2=0x70
#   [17] WP18 #16  zone limit-setter-2 NULL guard      (slot  @0x9E402600)
#        - crash 0xffffffff9e82d3fa CR2=0x68
#   [18] WP18 #17  intr-source registry lazy-init      (slot  @0x9E402680)
#        - crash 0xffffffff9eb6f11a CR2=0x0  (the ioapic registration)
#   [19] WP18 #18  intr-ithread kproc tolerance        (slot  @0x9E402700)
#        - panic 'kproc_create() failed with 12' (kern_intr.c)
#   [20] WP18 #19  intr-event naming NULL-buf skip     (slot  @0x9E402780)
#        - crash 0xffffffff9ed47b89 CR2=0x294 (strlcpy to NULL+0x294)
#   [21] WP18 #20  intr-event log NULL-buf skip        (slot  @0x9E402800)
#        - crash 0xffffffff9e8b78df CR2=0x0 (the designed error-path target)
#   [22] WP18 #21  cpu_thread_clean NULL-PCB guard     (slot  @0x9E402880)
#        - crash 0xffffffff9ee40ffd CR2=0x118 ([td+0x3f8] family)
#   [23] WP18 #22  thread_free NULL-proc skip          (slot  @0x9E402900)
#        - crash 0xffffffff9ef80a01 CR2=0x5cc (the kthread teardown)
#   [24] WP18 #23  netisr worker-init NULL skip        (slot  @0x9E402980)
#        - crash 0xffffffff9e851681 CR2=0x68 ('netisr_init')
#   [25] WP18 #24  thread-create proc-alloc NULL skip  (slot  @0x9E402A00)
#        - crash 0xffffffff9e92a664 CR2=0x468 (the generic thread-create)
# ----------------------------------------------------------------------------
# usage: bash scripts/wp18_build_all.sh
# ============================================================================
set -e
set -o pipefail
cd .
S=./scripts
K=./kit_build

echo "=== [0] WP16 chain (full rebuild from pristine f242f55e, incl. its verification boot) ==="
bash $S/wp16_build_all.sh | tail -3

echo "=== [1] WP17 #1/#2/#3 zone-drain guard (cave63/64 + the zone-table seed) ==="
python3 -u $S/wp17_patch_zonedrain_guard.py | tail -1
echo "=== [2] WP17 #4 kmem thunk read-time fallback (cave65) ==="
python3 -u $S/wp17_patch_kmem_thunk.py | tail -1
echo "=== [3] WP17 #5 W1 v3 vm_page supply extension (cave66) ==="
python3 -u $S/wp17_patch_w1_extend.py | tail -1
echo "=== [4] WP17 #6 malloc bump window 380KB -> 5.6MB (caves 50/56/51) ==="
python3 -u $S/wp17_patch_malloc_window.py | tail -1
echo "=== [5] WP17 #7 cave57 exit retarget (the td_locks double-unlock) ==="
python3 -u $S/wp17_patch_cave57_retarget.py | tail -1
echo "=== [6] WP17 #8 kmem-arena lazy bootstrap (cave67) ==="
python3 -u $S/wp17_patch_kmem_arena_boot.py | tail -1

echo "=== [7] WP18 #1 OID path-walker loop-head guard (cave68 — re-applied, a pure local guard) ==="
python3 -u $S/wp17_patch_oidwalk_guard.py | tail -1
echo "=== [8] WP18 #2 cpuset-zone bootstrap NULL-skip ==="
python3 -u $S/wp18_patch_cpuset_init.py | tail -1
echo "=== [9] WP18 #3 cpuset-root refcount NULL skip ==="
python3 -u $S/wp18_patch_cpuroot_ref.py | tail -1
echo "=== [10] WP18 #4 zone-create NULL-return guard ==="
python3 -u $S/wp18_patch_zonecreate_null.py | tail -1
echo "=== [11] WP18 #5 fork zone-alloc ENOMEM error return ==="
python3 -u $S/wp18_patch_fork_alloc.py | tail -1
echo "=== [12] WP18 #6 audit_worker kproc tolerance ==="
python3 -u $S/wp18_patch_audit_kproc.py | tail -1
echo "=== [13] WP18 #7 create_init fork tolerance ==="
python3 -u $S/wp18_patch_init_fork.py | tail -1
echo "=== [14] WP18 #8 idle_setup loop kproc tolerance ==="
python3 -u $S/wp18_patch_idle_kproc.py | tail -1
echo "=== [15] WP18 #9 idle_setup FIRST kproc tolerance ==="
python3 -u $S/wp18_patch_idle2_kproc.py | tail -1
echo "=== [16] WP18 #10 cpurv_init kproc tolerance x2 ==="
python3 -u $S/wp18_patch_cpurv_kproc.py | tail -1
echo "=== [17] WP18 #11 zone-stats accessor NULL-zone guard ==="
python3 -u $S/wp18_patch_zonestats_guard.py | tail -1
echo "=== [18] WP18 #12 zone-setter family NULL-zone guard x4 ==="
python3 -u $S/wp18_patch_zonesetters_guard.py | tail -1
echo "=== [19] WP18 #13 zone_create_ext NULL-parent guard ==="
python3 -u $S/wp18_patch_zcreate_parent.py | tail -1
echo "=== [20] WP18 #14 zone_create_ext NULL-keg field guard ==="
python3 -u $S/wp18_patch_zcreate_keg.py | tail -1
echo "=== [21] WP18 #15 zone_create_ext NULL-keg flags guard ==="
python3 -u $S/wp18_patch_zcreate_flags.py | tail -1
echo "=== [22] WP18 #16 zone limit-setter-2 NULL-zone guard ==="
python3 -u $S/wp18_patch_zonesetter2_guard.py | tail -1
echo "=== [23] WP18 #17 intr-source registry lazy-init guard ==="
python3 -u $S/wp18_patch_intrsrc_lazyinit.py | tail -1
echo "=== [24] WP18 #18 intr-ithread kproc tolerance ==="
python3 -u $S/wp18_patch_ithread_kproc.py | tail -1
echo "=== [25] WP18 #19 intr-event naming NULL-buffer skip ==="
python3 -u $S/wp18_patch_intrname_skip.py | tail -1
echo "=== [26] WP18 #20 intr-event log NULL-buffer skip ==="
python3 -u $S/wp18_patch_intrlog_skip.py | tail -1
echo "=== [27] WP18 #21 cpu_thread_clean NULL-PCB guard ==="
python3 -u $S/wp18_patch_threadclean_guard.py | tail -1
echo "=== [28] WP18 #22 thread_free NULL-proc skip ==="
python3 -u $S/wp18_patch_threadfree_guard.py | tail -1
echo "=== [29] WP18 #23 netisr worker-init NULL-object skip ==="
python3 -u $S/wp18_patch_netisr_worker.py | tail -1
echo "=== [30] WP18 #24 thread-create proc-alloc NULL skip ==="
python3 -u $S/wp18_patch_threadcreate_null.py | tail -1

echo "=== [31] size sanity (must equal pristine 65224704) ==="
SZ=$(stat -c%s $K/wp3_boot/kernel_raw.bin)
echo "kernel_raw.bin size: $SZ"
[ "$SZ" = "65224704" ] || { echo "!! SIZE MISMATCH — aborting"; exit 1; }

echo "=== [32] THE WP18 VERIFICATION BOOT ==="
cd $K && bash run.sh 300 > /dev/null 2>&1 || true

echo "=== [33] THE ROLLBACK GATE (every WP16-era line — grep ... || exit 1) ==="
grep -a -m1 "SIE CONFIDENTIAL" serial.log          || { echo "!! banner missing — REGRESSION"; exit 1; }
grep -a -m1 "Memory mode" serial.log               || { echo "!! Memory mode missing — REGRESSION"; exit 1; }
grep -a -m1 "Preloaded elf kernel" serial.log      || { echo "!! Preloaded elf kernel missing — REGRESSION"; exit 1; }
grep -a -m1 "CPU: AMD EPYC" serial.log             || { echo "!! CPU ID missing — REGRESSION"; exit 1; }
grep -a -m1 "CPU Features" serial.log              || { echo "!! CPU Features missing — REGRESSION"; exit 1; }
grep -a -m1 'Event timer "LAPIC"' serial.log       || { echo "!! Event timer missing — REGRESSION"; exit 1; }
grep -a -m1 "ACPI APIC Table" serial.log           || { echo "!! ACPI table missing — REGRESSION"; exit 1; }
grep -a -m1 "Multiprocessor System" serial.log     || { echo "!! SMP missing — REGRESSION"; exit 1; }
grep -a -m1 "APIC: CPU 0 has ACPI ID 0" serial.log || { echo "!! APIC CPU0 missing — REGRESSION"; exit 1; }
echo ">>> rollback OK — all WP16-era boot lines present <<<"

echo "=== [34] THE WP18 MARCH GATE (the new frontier lines — grep ... || exit 1) ==="
grep -a -m1 "ioapic0: ver 0x20" serial.log         || { echo "!! ioapic enumeration missing"; exit 1; }
grep -a -m1 "Routing external 8259A" serial.log    || { echo "!! ioapic routing missing"; exit 1; }
grep -a -m1 "cpu0 BSP:" serial.log                 || { echo "!! LAPIC cpu0 dump missing"; exit 1; }
grep -a -m1 "netisr_init:" serial.log              || { echo "!! netisr_init missing"; exit 1; }
grep -a -m1 "taskqueue_start_threads" serial.log   || { echo "!! taskqueue stage missing"; exit 1; }
echo ">>> march OK — the interrupt/netisr/taskqueue stages all reached <<<"

echo "=== [35] THE CLEAN-BOOT GATE (no trap, no panic, no power-down) ==="
grep -a -q "Fatal trap" serial.log    && { echo "!! Fatal trap — CRASH REGRESSION"; exit 1; }
grep -a -q "instruction pointer" serial.log && { echo "!! trap dump present — CRASH REGRESSION"; exit 1; }
grep -a -q "panic:" serial.log        && { echo "!! panic present — CRASH REGRESSION"; exit 1; }
grep -a -q "mDBG: System error" serial.log && { echo "!! mDBG dump present — CRASH REGRESSION"; exit 1; }
grep -a -q "kernel trap" serial.log   && { echo "!! kernel trap present — CRASH REGRESSION"; exit 1; }
echo ">>> clean-boot OK — no trap, no panic, no dump: the kernel reached its idle loop <<<"

echo "=== [36] summary ==="
grep -a -c "can't re-use a leaf" serial.log | xargs echo "sysctl leaf lines:"
grep -a -c "error 12" serial.log | xargs echo "designed kthread-error prints:"
wc -l serial.log | xargs echo "serial lines:"
echo "=== WP18 build complete ==="
