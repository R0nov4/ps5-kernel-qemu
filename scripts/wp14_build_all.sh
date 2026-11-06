#!/bin/bash
# ============================================================================
# WP14 — full reproducible build of the PS5 13.60 boot kit
# pristine WP7 base -> WP12 chain (no boot) -> WP13 chain (no boot)
#   + WP14:
#       A  arena bootstrap + fake extend callback (cave22 @0x9E400000
#          CC-island): node chains (1024x0x40 per arena), chunk-hash arrays,
#          order buckets zeroed, extent-list self-anchors, extend thunk
#          redirect -> bump allocator over DMAP [0x3F200000,0x40000000)
#          (advance capped at 1MB; scratch @DMAP(0x3F004000))
#          THE FIX THAT BOOTS vm_page_startup (was: infinite
#          msleep("kernel arena") -> sleepq_add -> td_sleepqueue NULL
#          -> crash 0x9f00a2e9 CR2=0x28)
#       B  sleepq_add td_sleepqueue guard (cave23 @0x9E400400):
#          [gs:0]->td_sleepqueue == NULL -> replicate the designed void
#          tail-exit (rdi = td_lock+0x18; tail-jmp 0x9e8b7520)
#       C  arena sleep -> designed error (jne->jmp @0x9e9d6c26): the
#          msleep block returns 0xc so vm_page_startup panics with the
#          CANONICAL 'panic: startup: no room for tables' instead of an
#          infinite sleep (safety net when the pool exhausts)
# usage: bash scripts/wp14_build_all.sh
# ============================================================================
set -e
set -o pipefail
cd .
S=./scripts
K=./kit_build

echo "=== [0] WP13 chain (WP7 base + WP9 + MADT + WP11 + WP12 + WP13), no boot ==="
WP13_NOBOOT=1 bash $S/wp13_build_all.sh "$@" | tail -3

echo "=== [1] WP14 arena bootstrap + sleepq guard + fail-safe ==="
python3 -u $S/wp14_patch_arena_boot.py | tail -2

echo "=== [2] verification boot ==="
if [ "$WP14_NOBOOT" = "1" ]; then
  echo "=== [2] SKIPPED verification boot (WP14_NOBOOT) ==="
else
cd $K && bash run.sh 300 > /dev/null 2>&1 || true
grep -a -m1 "SIE CONFIDENTIAL" serial.log || echo "!! banner missing"
grep -a -m1 "Memory mode" serial.log || echo "!! Memory mode missing"
grep -a -c "can't re-use a leaf" serial.log | xargs echo "sysctl leaf lines:"
grep -a -m1 "CPU Features" serial.log || echo "!! CPU Features missing"
grep -a -m1 "instruction pointer" serial.log || echo "(no crash — clean boot!)"
grep -a -m1 "panic:" serial.log || true
wc -l serial.log | xargs echo "serial lines:"
fi
echo "=== WP14 build complete ==="
