#!/bin/bash
# ============================================================================
# WP20 — THE USER'S 9 PRECISE PLANS + THE NEW-FRONTIER FAMILIES
#         (done 734 -> 1006+/1236, ZERO crashes) + THE FULL GATE SUITE
# ----------------------------------------------------------------------------
# THE WP19 REGRESSION (rolled back, the user's iron directive #1): cave80..94
#   and the 14 wp19_patch_*.py NEVER run here — [0] rebuilds the golden WP18
#   image from the pristine base through the proven WP16->WP17->WP18 chain.
#   fork1/proc_create KEEP their designed error-12 semantics: no allocator
#   paths, no .data seeds, no subsystem activation.
#
# THE WP20 METHOD (the user's directive #2): FIFTEEN comprehensive patch
#   groups — the user's 9 precise plans applied verbatim, then 6 more
#   new-frontier families found by fastboot->disasm->guard cycles (each
#   patch docstring carries its own root-cause + GDB forensics):
#
#   G1  the GEOM unlock            (the user's plan #1: 75 4a -> eb 4a
#       @0x9ebabaad)               — SYSINIT IDX 735 unstuck, 'firmware taskq'
#   G2  newbus devclass lazy-init  (the user's plan #2: 0x9e6a2535,
#       HEAD 0x9FE84160/TAIL 0x9FE84168) — 'random: entropy device ...'
#   G3  entropy-device NULL-array  (the user's plan #3: 0x9e71c9dc ->
#       the designed empty path 0x9e71ca6b) — 'mem:', 'null:', GEOM_SCHED
#   G4  contigmalloc/vm_phys fail-fast family (the user's plan #4: the
#       retry -> the designed exhaustion exit 0x9e8f3ad0 + the rdi==NULL
#       guards 0x9e9d7750/0x9e82c0c0) — 'contigmalloc failed.', pfsmgr
#   G5  SceIpmiMgr ENOMEM          (the user's plan #5: the evhand entry
#       0x9ebd1da0 answers 12, the body 0x9ebd2070 shielded)
#   G6  plinks.q assert NOP + segment-lookup guard (the user's plan #6:
#       0x9ef7c26c + [rdi+0x30]==0 @0x9ea055b0) — hmd2_imu, 'io: <I/O>'
#   G7  xsave -> fxsave fallback   (the user's plan #7: je->jmp
#       @0x9eb21dec, the designed legacy path 0x9eb21e01)
#   G8  'da' TAILQ lazy-init + AES entry guard (the user's plan #8:
#       0x9eac2af6 + the -1 answer @0x9ebf43fd's fn)
#   G9  dmem + mDBG trio + dce     (the user's plan #9: 0x9e7c0f13 +
#       [0xa21e31e0] @0x9f070220/370/4d0 + 0x9ea84ff0)
#   G10 the domain free-node pop family (3 guards: the two designed
#       engine skips + the node-create no-op — closes all four pop paths)
#   G11 the stats-table NULL guards, read + write twins (0xa1f9a538)
#   G12 the hrtimer + polling-timer NULL-path panics -> own epilogues
#   G13 the deep-march NULL-skip family (if_attach record, 16KB-contig
#       thunk, zone-item register)
#   G14 the dmem window-tuner skip + the name-registry TAILQ lazy-init
#   G15 the MP3 NULL-buffer init skip (memset(NULL,0x2818) -> the
#       designed EINVAL exit)
#
# GATES (the user's iron directive #3 — every one `|| exit 1`, the WP19
#   violation can never happen again):
#   [G1..G9]   the 9 WP16 rollback gates  (banner ... APIC: CPU 0)
#   [G10..G14] the 5 WP18 march gates    (ioapic0 ... taskqueue)
#   [G15..G21] the 7 WP20 march gates    (firmware taskq ... io: <I/O>)
#   [G22]      THE CLEAN-BOOT GATE (strict WP18 form: no trap, no panic,
#              no dump, no trap spam — the kernel marches on, alive)
#   [G23]      THE DONE-COUNTER GATE     (done >= 1000, GDB-measured)
#
# RESULT (this build, GDB-measured): done = 1006/1236, ZERO crash lines,
#   the march's deepest landmark 'hdcp packet is set to 1'; the next
#   documented frontier (the si_sub 0x14+ families toward 'Device
#   configuration finished.') is the WP21 target.
#
# usage: bash scripts/wp20_build_all.sh
# ============================================================================
set -e
set -o pipefail
cd .
S=./scripts
K=./kit_build

echo "=== [0] THE ROLLBACK — full rebuild from pristine (WP16 chain incl. its verification boot) ==="
bash $S/wp16_build_all.sh | tail -3

echo "=== [1] WP17 #1..#8 (the WP18-kept zone/malloc/window family) ==="
python3 -u $S/wp17_patch_zonedrain_guard.py  | tail -1
python3 -u $S/wp17_patch_kmem_thunk.py       | tail -1
python3 -u $S/wp17_patch_w1_extend.py        | tail -1
python3 -u $S/wp17_patch_malloc_window.py    | tail -1
python3 -u $S/wp17_patch_cave57_retarget.py  | tail -1
python3 -u $S/wp17_patch_kmem_arena_boot.py  | tail -1

echo "=== [2] WP18 #1..#24 (the golden WP18 stack — the real-machine baseline) ==="
python3 -u $S/wp17_patch_oidwalk_guard.py          | tail -1
python3 -u $S/wp18_patch_cpuset_init.py            | tail -1
python3 -u $S/wp18_patch_cpuroot_ref.py            | tail -1
python3 -u $S/wp18_patch_zonecreate_null.py        | tail -1
python3 -u $S/wp18_patch_fork_alloc.py             | tail -1
python3 -u $S/wp18_patch_audit_kproc.py            | tail -1
python3 -u $S/wp18_patch_init_fork.py              | tail -1
python3 -u $S/wp18_patch_idle_kproc.py             | tail -1
python3 -u $S/wp18_patch_idle2_kproc.py            | tail -1
python3 -u $S/wp18_patch_cpurv_kproc.py            | tail -1
python3 -u $S/wp18_patch_zonestats_guard.py        | tail -1
python3 -u $S/wp18_patch_zonesetters_guard.py      | tail -1
python3 -u $S/wp18_patch_zcreate_parent.py         | tail -1
python3 -u $S/wp18_patch_zcreate_keg.py            | tail -1
python3 -u $S/wp18_patch_zcreate_flags.py          | tail -1
python3 -u $S/wp18_patch_zonesetter2_guard.py      | tail -1
python3 -u $S/wp18_patch_intrsrc_lazyinit.py       | tail -1
python3 -u $S/wp18_patch_ithread_kproc.py          | tail -1
python3 -u $S/wp18_patch_intrname_skip.py          | tail -1
python3 -u $S/wp18_patch_intrlog_skip.py           | tail -1
python3 -u $S/wp18_patch_threadclean_guard.py      | tail -1
python3 -u $S/wp18_patch_threadfree_guard.py       | tail -1
python3 -u $S/wp18_patch_netisr_worker.py          | tail -1
python3 -u $S/wp18_patch_threadcreate_null.py      | tail -1

echo "=== [3] WP20 — the 15 comprehensive patch groups (the user's 9 plans + 6 frontier families) ==="
echo "--- G1  the GEOM unlock (the user's plan #1) ---"
python3 -u $S/wp20_patch_g1_geom.py            | tail -1
echo "--- G2  the newbus devclass lazy-init (plan #2) ---"
python3 -u $S/wp20_patch_g2_devclass.py        | tail -1
echo "--- G3  the entropy NULL-array guard (plan #3) ---"
python3 -u $S/wp20_patch_g3_entropy.py         | tail -1
echo "--- G4  the contigmalloc/vm_phys fail-fast family (plan #4) ---"
python3 -u $S/wp20_patch_g4_contig.py          | tail -1
echo "--- G5  the SceIpmiMgr ENOMEM tolerance (plan #5) ---"
python3 -u $S/wp20_patch_g5_ipmimgr.py         | tail -1
echo "--- G6  the plinks/segment-lookup guards (plan #6) ---"
python3 -u $S/wp20_patch_g6_plinks.py          | tail -1
echo "--- G7  the xsave->fxsave fallback (plan #7) ---"
python3 -u $S/wp20_patch_g7_fxsave.py          | tail -1
echo "--- G8  the 'da' TAILQ + AES guards (plan #8) ---"
python3 -u $S/wp20_patch_g8_tailq_aes.py       | tail -1
echo "--- G9  the dmem/mDBG/dce family (plan #9) ---"
python3 -u $S/wp20_patch_g9_dmem_mdbg_dce.py   | tail -1
echo "--- G10 the domain free-node pop family ---"
python3 -u $S/wp20_patch_g10_popfamily.py      | tail -1
echo "--- G11 the stats-table NULL guards (read+write) ---"
python3 -u $S/wp20_patch_g11_statstable.py     | tail -1
echo "--- G12 the hrtimer/polling-timer family ---"
python3 -u $S/wp20_patch_g12_timerfamily.py    | tail -1
echo "--- G13 the deep-march NULL-skip family ---"
python3 -u $S/wp20_patch_g13_deepmarch.py      | tail -1
echo "--- G14 the tuner skip + registry TAILQ lazy-init ---"
python3 -u $S/wp20_patch_g14_tuner_registry.py | tail -1
echo "--- G15 the MP3 NULL-buffer init skip ---"
python3 -u $S/wp20_patch_g15_mp3buf.py         | tail -1

echo "=== [4] size sanity (must equal pristine 65224704) ==="
SZ=$(stat -c%s $K/wp3_boot/kernel_raw.bin)
echo "kernel_raw.bin size: $SZ"
[ "$SZ" = "65224704" ] || { echo "!! SIZE MISMATCH — aborting"; exit 1; }

echo "=== [5] THE WP20 VERIFICATION BOOT (patient — the deep SYSINITs take minutes under TCG) ==="
cd $K
rm -f serial.log
bash $S/wp20_patient_boot.sh 13 serial.log > /tmp/wp20_boot_progress.txt 2>&1 || true
tail -4 serial.log

echo "=== [6] THE 9 WP16 ROLLBACK GATES (grep ... || exit 1) ==="
grep -a -m1 "SIE CONFIDENTIAL" serial.log          || { echo "!! banner missing — REGRESSION"; exit 1; }
grep -a -m1 "Memory mode" serial.log               || { echo "!! Memory mode missing — REGRESSION"; exit 1; }
grep -a -m1 "Preloaded elf kernel" serial.log      || { echo "!! Preloaded elf kernel missing — REGRESSION"; exit 1; }
grep -a -m1 "CPU: AMD EPYC" serial.log             || { echo "!! CPU ID missing — REGRESSION"; exit 1; }
grep -a -m1 "CPU Features" serial.log              || { echo "!! CPU Features missing — REGRESSION"; exit 1; }
grep -a -m1 'Event timer "LAPIC"' serial.log       || { echo "!! Event timer missing — REGRESSION"; exit 1; }
grep -a -m1 "ACPI APIC Table" serial.log           || { echo "!! ACPI table missing — REGRESSION"; exit 1; }
grep -a -m1 "Multiprocessor System" serial.log     || { echo "!! SMP missing — REGRESSION"; exit 1; }
grep -a -m1 "APIC: CPU 0 has ACPI ID 0" serial.log || { echo "!! APIC CPU0 missing — REGRESSION"; exit 1; }
echo ">>> WP16 rollback OK — all 9 early-boot lines present <<<"

echo "=== [7] THE 5 WP18 MARCH GATES (grep ... || exit 1) ==="
grep -a -m1 "ioapic0: ver 0x20" serial.log         || { echo "!! ioapic enumeration missing"; exit 1; }
grep -a -m1 "Routing external 8259A" serial.log    || { echo "!! ioapic routing missing"; exit 1; }
grep -a -m1 "cpu0 BSP:" serial.log                 || { echo "!! LAPIC cpu0 dump missing"; exit 1; }
grep -a -m1 "netisr_init:" serial.log              || { echo "!! netisr_init missing"; exit 1; }
grep -a -m1 "taskqueue_start_threads" serial.log   || { echo "!! taskqueue stage missing"; exit 1; }
echo ">>> WP18 march OK — the interrupt/netisr/taskqueue stages all reached <<<"

echo "=== [8] THE 7 WP20 MARCH GATES (grep ... || exit 1) ==="
grep -a -m1 "taskq" serial.log                     || { echo "!! GEOM firmware taskq stage missing"; exit 1; }
grep -a -m1 "random: entropy device external interface" serial.log || { echo "!! entropy stage missing"; exit 1; }
grep -a -m1 "mem: <memory>" serial.log             || { echo "!! mem device missing"; exit 1; }
grep -a -m1 "null: <full device" serial.log        || { echo "!! null device missing"; exit 1; }
grep -a -m1 "GEOM_SCHED" serial.log                || { echo "!! GEOM_SCHED stage missing"; exit 1; }
grep -a -m1 "contigmalloc failed." serial.log      || { echo "!! contigmalloc fail-fast missing"; exit 1; }
grep -a -m1 "io: <I/O>" serial.log                 || { echo "!! io device missing"; exit 1; }
echo ">>> WP20 march OK — the deep-boot stages all reached <<<"

echo "=== [9] THE CLEAN-BOOT GATE (strict WP18 form — || exit 1) ==="
grep -a -q "Fatal trap" serial.log          && { echo "!! Fatal trap — CRASH REGRESSION"; exit 1; }
grep -a -q "instruction pointer" serial.log && { echo "!! trap dump present — CRASH REGRESSION"; exit 1; }
grep -a -q "panic:" serial.log              && { echo "!! panic present — CRASH REGRESSION"; exit 1; }
grep -a -q "mDBG: System error" serial.log  && { echo "!! mDBG dump present — CRASH REGRESSION"; exit 1; }
grep -a -q "kernel trap" serial.log         && { echo "!! kernel trap present — CRASH REGRESSION"; exit 1; }
grep -a -q "double fault" serial.log        && { echo "!! double fault — CRASH REGRESSION"; exit 1; }
grep -a -m1 "hdcp packet is set to 1" serial.log || { echo "!! the WP20 frontier landmark missing"; exit 1; }
echo ">>> CLEAN-BOOT OK — zero crash lines, the march reached the hdcp frontier alive <<<"

echo "=== [10] THE DONE-COUNTER GATE (done >= 1000, GDB-measured) ==="
bash $S/wp20_gdb_run.sh "hdcp packet" /tmp/wp20_done_serial.log 30 > /tmp/wp20_done_out.txt 2>&1 || true
DONE=$(grep -a -o "done-stamped=[0-9]*" /tmp/wp20_done_out.txt | head -1 | cut -d= -f2)
echo "done = ${DONE:-0} / 1236"
[ -n "$DONE" ] && [ "$DONE" -ge 1000 ] || { echo "!! done counter ${DONE:-unreadable} < 1000 — FAIL"; exit 1; }
echo ">>> done-counter OK — the 1000+ target met <<<"

echo "=== [11] summary ==="
grep -a -c "error 12" serial.log | xargs echo "designed kthread-error prints:"
grep -a -c "module_register_init" serial.log | xargs echo "module registrations reached:"
grep -a -c "GEOM_PART" serial.log | xargs echo "GEOM_PART scheme registrations:"
wc -l serial.log | xargs echo "serial lines:"
echo "=== WP20 build complete — done=${DONE}/1236, all 23 gates green ==="
