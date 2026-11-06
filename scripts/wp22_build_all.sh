#!/bin/bash
# ============================================================================
# WP22 — THE LANDMARK ROUND: 'Device configuration finished.' + THE G26 PARK
#         (10 comprehensive patch groups G29..G38 on the WP21 chain)
# ----------------------------------------------------------------------------
# THE ROUND LAWS (the user's iron directives, inherited from WP21):
#   [0] NO wp16_build_all.sh from scratch — the base is the golden WP20
#       image shipped in the kit (wp20_golden_kernel_raw.bin, md5
#       81a437245258e16d9296fb259002f3df, done=1006, 23 gates green).
#   [1] The full chain — 13 WP21 scripts + 10 WP22 scripts — rebuilds the
#       delivered boot-verified image BYTE-EXACTLY: md5
#       2f821627fc6f9277b30c0ca9d60b6e5c (gate [3] below). The build
#       without the boot takes under two minutes.
#   [2] The verification boot + the GDB done-probe are the LAST steps;
#       every gate is `|| exit 1`.
#
# THE 10 COMPREHENSIVE PATCH GROUPS (all on the WP21 image):
#   G29 v2 THE FAULT-FREE SOFTWARE PAGE WALK — the whole pmap_kextract
#       (entry 0x9ecce330) replaced with a CR3 walk through the DMAP
#       only (slot 0x9E404000): 1GB/2MB/4K pages handled, unmapped VAs
#       answer 0 — no self-map dependency, NO POSSIBLE FAULT. The GDB
#       probe proved the v1 slow path faults translating an unmapped
#       low VA (PML4[0] absent in the kernel's own tables).
#   G30 THE MAPPED-DEST/SRC MEMCPY ORACLE GUARD — G21's hook
#       (0x9e6490b4) redirected to slot 0x9E404180: after the canonical
#       checks the stub calls the G29 walk on DEST and SRC — a zero
#       answer means the page is UNMAPPED -> the designed 0xffffffdb
#       residual-pointer error (found by the G29v2 boot: trap 12
#       @0x9e6490e5, CR2=0xffffff8098beb800, canonical-but-unmapped).
#   G31 v3 THE DUMP-REGION SCRATCH POINTER — [0xA18EA020] =
#       0xFFFF8E7740000000 = DMAP(phys 0x40000000): outside the G22
#       bump window, mapped, zeroed, never allocated — the faithful
#       Sony-loader preload (the init fn then skips its contigmalloc).
#   G32 THE DUMP-RECORD EMITTER GATE — the entry gate's je forced to
#       jmp @0x9E826307: the emitter always answers its own designed
#       0xffffffdb 'record not available' skip.
#   G33 THE DUMP-NOTIFIER NULL-CTX GUARD — 0x9e825aae (rdi=ctx=NULL,
#       CR2=0x10) -> slot 0x9E404400: NULL answers 0 through the fn's
#       own unwind; live ctx replays the original instructions.
#   G34 THE SBL-SERVICE NULL-ARG GUARD — 0x9e8da8be (rdi=NULL, CR2=0x64)
#       -> slot 0x9E404480: the designed NULL 'nothing found' answer.
#   G35 THE contigmalloc(ccp) INIT TOLERANCE — the error jump
#       retargeted (je 0x17 -> je 0x0f @0x9EA9768E) from the
#       panic('contigmalloc(ccp)') block to the fn's own clean
#       epilogue (xor eax,eax; add rsp,0x10; pop rbp; ret).
#   G36 THE contigmalloc(infl) INIT TOLERANCE — the panic je NOPed
#       (74 06 -> 90 90 @0x9EF84A42): the NULL allocation falls
#       through into the fn's own clean epilogue.
#   G37 THE BZERO/MEMSET NULL-DEST ORACLE GUARD — the bzero family
#       entry (0x9e648ff4, rep stosq crashed @0x9e649024 with
#       CR2=0x0) -> slot 0x9E404500: canonical + kextract-oracle on
#       the dest; NULL/unmapped answers the C memset contract (returns
#       dest) without touching memory.
#   G38 THE GBASE-MODULE DESIGNED LOAD-FAILURE — the module's modevent
#       handler (0x9EED4320, the NULL-deref minefield that killed the
#       march @0x9eed45fe) -> slot 0x9E404580: 'mov eax,0xc; ret' —
#       'MOD_LOAD (sdma/gbase) error 12', the same tolerance this very
#       boot already exercises for pcist / sm_service / sbl_sm_service.
#
# GATES (every one `|| exit 1`):
#   [3]        THE BYTE-EXACT REBUILD GATE (md5 2f821627fc6f9277b30c...)
#   [G1..G9]   the 9 WP16 rollback gates   (banner ... APIC: CPU 0)
#   [G10..G14] the 5 WP18 march gates      (ioapic0 ... taskqueue)
#   [G15..G21] the 7 WP20 march gates      (taskq ... io: <I/O>)
#   [G22]      the STRICT clean-boot gate  (zero crash lines + hdcp)
#   [G23]      the WP21 MP1 gate           (8x init_cpupstate)
#   [G24..G30] the 7 WP22 march gates      (mp1 dump ... vcn error 45)
#   [G31]      the WP22 landmark gate      ('Device configuration finished.')
#   [G32]      the WP22 terminal-state gate (the log ENDS at the landmark)
#   [G33]      the done-counter gate       (GDB, done >= 1078 at the park)
#
# usage: bash scripts/wp22_build_all.sh          (from the kit root)
# ============================================================================
set -e
set -o pipefail
cd "$(dirname "$0")/.."
KIT=$(pwd)
S=$KIT/scripts

# --- QEMU / GDB detection (the run.sh convention + the build-sandbox path) ---
QEMU=${QEMU:-$(command -v qemu-system-x86_64 || true)}
[ -z "$QEMU" ] && [ -x /usr/lib/qemu/qemu-system-x86_64 ] && QEMU=/usr/lib/qemu/qemu-system-x86_64
if [ -z "$QEMU" ] && [ -x ./qemu-local/root/usr/bin/qemu-system-x86_64 ]; then
  QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64
  export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
fi
GDB=${GDB:-$(command -v gdb || true)}
[ -z "$GDB" ] && [ -x ./qemu-local/root/usr/bin/gdb ] && GDB=./qemu-local/root/usr/bin/gdb

echo "=== [0] THE BASE — the golden WP20 image (NO wp16 rebuild — the anti-timeout law) ==="
cp -f wp20_golden_kernel_raw.bin wp3_boot/kernel_raw.bin
md5sum wp3_boot/kernel_raw.bin
[ "$(md5sum wp3_boot/kernel_raw.bin | cut -d' ' -f1)" = "81a437245258e16d9296fb259002f3df" ] \
  || { echo "!! golden base corrupted — aborting"; exit 1; }

echo "=== [1] THE WP21 CHAIN (G16..G28 — the done=1006 unstuck + the frontier stop) ==="
python3 -u $S/wp21_patch_g16_hvwait.py       | tail -1
python3 -u $S/wp21_patch_g17_statspoll.py    | tail -1
python3 -u $S/wp21_patch_g18_socpci.py       | tail -1
python3 -u $S/wp21_patch_g19_umcbsf.py       | tail -1
python3 -u $S/wp21_patch_g20_regerrh.py      | tail -1
python3 -u $S/wp21_patch_g21_memcpy.py       | tail -1
python3 -u $S/wp21_patch_g22_contigfree.py   | tail -1
python3 -u $S/wp21_patch_g23_ptlookup.py     | grep "^OK" | tail -1
python3 -u $S/wp21_patch_g24_procdesc.py     | tail -1
python3 -u $S/wp21_patch_g25_unpinit.py      | tail -1
python3 -u $S/wp21_patch_g26_frontier_stop.py | tail -1
python3 -u $S/wp21_patch_g27_cpupstate.py    | tail -1
python3 -u $S/wp21_patch_g28_apicvector.py   | tail -1

echo "=== [2] THE WP22 CHAIN (G29..G38 — the landmark round) ==="
python3 -u $S/wp22_patch_g29_kextract.py     | tail -1
python3 -u $S/wp22_patch_g30_memcpy.py       | tail -1
python3 -u $S/wp22_patch_g31_dumpregion.py   | tail -1
python3 -u $S/wp22_patch_g32_emittergate.py  | tail -1
python3 -u $S/wp22_patch_g33_notifier.py     | tail -1
python3 -u $S/wp22_patch_g34_sblsvc.py       | tail -1
python3 -u $S/wp22_patch_g35_contigccp.py    | tail -1
python3 -u $S/wp22_patch_g36_contiginfl.py   | tail -1
python3 -u $S/wp22_patch_g37_memset.py       | tail -1
python3 -u $S/wp22_patch_g38_gbasemod.py     | tail -1

echo "=== [3] THE BYTE-EXACT REBUILD GATE (size + md5 — the delivered image) ==="
SZ=$(stat -c%s wp3_boot/kernel_raw.bin)
echo "kernel_raw.bin size: $SZ"
[ "$SZ" = "65224704" ] || { echo "!! SIZE MISMATCH — aborting"; exit 1; }
MD5=$(md5sum wp3_boot/kernel_raw.bin | cut -d' ' -f1)
echo "kernel_raw.bin md5: $MD5"
[ "$MD5" = "2f821627fc6f9277b30c0ca9d60b6e5c" ] \
  || { echo "!! REBUILD NOT BYTE-EXACT (expected 2f821627fc6f9277b30c0ca9d60b6e5c) — aborting"; exit 1; }
echo ">>> REBUILD OK — byte-identical to the delivered boot-verified image <<<"

echo "=== [4] THE WP22 VERIFICATION BOOT (patient; the TCG march is slow) ==="
[ -x "$QEMU" ] || { echo "qemu-system-x86_64 not found — install qemu-system-x86"; exit 1; }
[ -f serial.log ] && cp -f serial.log serial.log.wp22   # preserve the delivered boot
rm -f serial.log
$QEMU -L ./bios -M pc -cpu EPYC -m 2G -smp 8 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=serial.log \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot 2>/dev/null &
QPID=$!
last=0; stall=0; hit=0
for i in $(seq 1 42); do
  sleep 20
  kill -0 $QPID 2>/dev/null || { echo "QEMU exited at $((i*20/60))m$((i*20%60))s"; break; }
  grep -a -q "Power down" serial.log 2>/dev/null && { echo "panic tail at $((i*20/60))m"; break; }
  grep -a -q "Device configuration finished" serial.log 2>/dev/null && hit=1
  L=$(wc -l < serial.log 2>/dev/null || echo 0)
  if [ "$L" = "$last" ]; then stall=$((stall+1)); else stall=0; fi
  echo "t=$((i*20/60))m$((i*20%60))s lines=$L stall=${stall} landmark=${hit}"
  last=$L
  [ $hit -eq 1 ] && [ $stall -ge 6 ] && { echo "(landmark + 2min silence — the G26 park)"; break; }
  [ $hit -eq 0 ] && [ $stall -ge 9 ] && { echo "(3min silence BEFORE the landmark — stall!)"; break; }
done
kill $QPID 2>/dev/null; wait 2>/dev/null
tail -4 serial.log

echo "=== [5] THE 9 WP16 ROLLBACK GATES (grep ... || exit 1) ==="
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

echo "=== [6] THE 5 WP18 MARCH GATES (grep ... || exit 1) ==="
grep -a -m1 "ioapic0: ver 0x20" serial.log         || { echo "!! ioapic enumeration missing"; exit 1; }
grep -a -m1 "Routing external 8259A" serial.log    || { echo "!! ioapic routing missing"; exit 1; }
grep -a -m1 "cpu0 BSP:" serial.log                 || { echo "!! LAPIC cpu0 dump missing"; exit 1; }
grep -a -m1 "netisr_init:" serial.log              || { echo "!! netisr_init missing"; exit 1; }
grep -a -m1 "taskqueue_start_threads" serial.log   || { echo "!! taskqueue stage missing"; exit 1; }
echo ">>> WP18 march OK — the interrupt/netisr/taskqueue stages all reached <<<"

echo "=== [7] THE 7 WP20 MARCH GATES (grep ... || exit 1) ==="
grep -a -m1 "taskq" serial.log                     || { echo "!! GEOM firmware taskq stage missing"; exit 1; }
grep -a -m1 "random: entropy device external interface" serial.log || { echo "!! entropy stage missing"; exit 1; }
grep -a -m1 "mem: <memory>" serial.log             || { echo "!! mem device missing"; exit 1; }
grep -a -m1 "null: <full device" serial.log        || { echo "!! null device missing"; exit 1; }
grep -a -m1 "GEOM_SCHED" serial.log                || { echo "!! GEOM_SCHED stage missing"; exit 1; }
grep -a -m1 "contigmalloc failed." serial.log      || { echo "!! contigmalloc fail-fast missing"; exit 1; }
grep -a -m1 "io: <I/O>" serial.log                 || { echo "!! io device missing"; exit 1; }
echo ">>> WP20 march OK — the deep-boot stages all reached <<<"

echo "=== [8] THE CLEAN-BOOT GATE (strict WP18 form — || exit 1) ==="
grep -a -q "Fatal trap" serial.log          && { echo "!! Fatal trap — CRASH REGRESSION"; exit 1; }
grep -a -q "instruction pointer" serial.log && { echo "!! trap dump present — CRASH REGRESSION"; exit 1; }
grep -a -q "panic:" serial.log              && { echo "!! panic present — CRASH REGRESSION"; exit 1; }
grep -a -q "mDBG: System error" serial.log  && { echo "!! mDBG dump present — CRASH REGRESSION"; exit 1; }
grep -a -q "kernel trap" serial.log         && { echo "!! kernel trap present — CRASH REGRESSION"; exit 1; }
grep -a -q "double fault" serial.log        && { echo "!! double fault — CRASH REGRESSION"; exit 1; }
grep -a -m1 "hdcp packet is set to 1" serial.log || { echo "!! the WP20 frontier landmark missing"; exit 1; }
echo ">>> CLEAN-BOOT OK — zero crash lines, the march passed the hdcp frontier alive <<<"

echo "=== [9] THE WP21 MP1 GATE (the 8-CPU cpupstate stage — || exit 1) ==="
CPUST=$(grep -a -c "init_cpupstate" serial.log || true)
echo "init_cpupstate lines: $CPUST"
[ "$CPUST" -ge 8 ] || { echo "!! the MP1 cpupstate stage incomplete (<8 CPUs)"; exit 1; }
echo ">>> WP21 march OK — the whole MP1 stage ran on all 8 CPUs <<<"

echo "=== [10] THE 7 WP22 MARCH GATES (the post-hdcp families — || exit 1) ==="
grep -a -m1 "Create mp1 dump" serial.log      || { echo "!! the MP1 dump stage missing (G29 territory)"; exit 1; }
grep -a -m1 "Create rlc dump" serial.log      || { echo "!! the RLC dump stage missing (G29 territory)"; exit 1; }
grep -a -m1 "MOD_LOAD (pcist" serial.log      || { echo "!! the pcist module stage missing (G32/G31 territory)"; exit 1; }
grep -a -m1 "sceSblServiceMailbox" serial.log || { echo "!! the SBL service layer missing (G33/G34 territory)"; exit 1; }
grep -a -m1 "MOD_LOAD (sdma" serial.log       || { echo "!! the sdma/gbase module tolerance missing (G38)"; exit 1; }
grep -a -m1 "SCECODECKMD" serial.log          || { echo "!! the codec-kmd stage missing (the post-gbase march)"; exit 1; }
grep -a -m1 "MOD_LOAD (vcn" serial.log        || { echo "!! the vcn module stage missing (the late module wave)"; exit 1; }
echo ">>> WP22 march OK — the dump, SBL, module and codec families all printed <<<"

echo "=== [11] THE WP22 LANDMARK + TERMINAL-STATE GATES (|| exit 1) ==="
grep -a -m1 "Device configuration finished." serial.log || { echo "!! THE WP22 LANDMARK MISSING — a pre-landmark blocker remains"; exit 1; }
LASTLINE=$(grep -a "." serial.log | tail -1)
echo "$LASTLINE" | grep -a -q "Device configuration finished." \
  || { echo "!! the log does not END at the landmark — output after the park: $LASTLINE"; exit 1; }
echo ">>> WP22 landmark OK — printed, and the log ends right there (the G26 park) <<<"

echo "=== [12] THE DONE-COUNTER GATE (GDB, done >= 1078 at the park) ==="
if [ -x "$GDB" ]; then
  rm -f /tmp/wp22_done_serial.log
  $QEMU -L ./bios -M pc -cpu EPYC -m 2G -smp 8 \
    -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
    -display none -serial null -monitor none \
    -chardev file,id=dbg,path=/tmp/wp22_done_serial.log \
    -device isa-debugcon,iobase=0x402,chardev=dbg \
    -gdb tcp::1234 -no-reboot 2>/dev/null &
  QPID=$!
  for i in $(seq 1 1320); do
    grep -a -q "Device configuration finished" /tmp/wp22_done_serial.log 2>/dev/null && break
    kill -0 $QPID 2>/dev/null || break
    sleep 1
  done
  sleep 10
  timeout 90 $GDB -q -batch -x $S/wp22_gdb_probe.gdb > /tmp/wp22_done_out.txt 2>&1 || true
  kill $QPID 2>/dev/null; wait 2>/dev/null
  DONE=$(grep -a -o "done-stamped=[0-9]*" /tmp/wp22_done_out.txt | head -1 | cut -d= -f2)
  echo "done = ${DONE:-0} / 1236 (expected ~1141 — the landmark entry is at sorted position 1140)"
  [ -n "$DONE" ] && [ "$DONE" -ge 1078 ] || { echo "!! done counter ${DONE:-unreadable} < 1078 — FAIL"; exit 1; }
else
  echo "!! gdb not found — the done-counter gate cannot run"; exit 1
fi

echo "=== [13] summary ==="
grep -a -c "error 12" serial.log | xargs echo "designed kthread/module error-12 prints:"
grep -a -c "module_register_init" serial.log | xargs echo "module registrations reached:"
grep -a -c "init_cpupstate" serial.log | xargs echo "MP1 cpupstate stage lines:"
grep -a -c "ERROR:" serial.log | xargs echo "tolerated error prints (sbl/dump/mp1 families):"
wc -l serial.log | xargs echo "serial lines (the last one is the landmark):"
echo "=== WP22 build complete — done=${DONE}/1236, all 33 gates green, md5 2f821627fc6f9277b30c0ca9d60b6e5c ==="
