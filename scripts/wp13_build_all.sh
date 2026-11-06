#!/bin/bash
# ============================================================================
# WP13 — full reproducible build of the PS5 13.60 boot kit
# pristine WP7 base -> WP12 chain (WP9..MADT..WP11..WP12, no boot)
#   + WP13 SYSINIT crash-fix series #1..#17:
#       #1  free()/contigfree NULL-descriptor guard (cave8)   0x9eff8e19
#       #2  mtx_lock fast-path bound 4 -> 0xf                 0x9e8b6c71
#       #3  zone-configure NULL-ctx guard (cave9)             0x9e82961a
#       #4  registry-create NULL-alloc abort (cave10)         0x9eff90e2
#       #5  malloc front-end NULL zone-table guard (cave11)   0x9eff8c48
#       #6  kern_env array slot NULL guard (cave12)           0x9e86e124
#       #7  sleep mtxpool NULL-alloc skip (cave13)            0x9ea668aa
#       #8  kern_env array -> seed page (cave15 @P5 body)     0x9e86dc22
#       #9  lock-setup leaf NULL-object guard (cave16)        0x9ee1e9d0
#       #10 mtx_init NULL/small-object entry guard (cave17)   0x9e8b7e35
#       #11 sysinit alloc-object NULL skip (cave18)           0x9e8e988c
#       #12 create-and-dispatch NULL-object skip (cave19)     0x9eb2dd7a
#       #13 lock-class node NULL skip (cave20)                0x9e8b8674
#       #14 link_elf_init NULL-file clean exit (je retarget)  panic link_elf
#       #15 linker-sysinit NULL-file skip (je epilogue)       0x9e943788
#       #16 linker-file processor NULL guard (cave21)         0x9e9431e9
#       #17 MSR-frequency div-by-zero guard (or edi,1)        trap 18
#     Cave relocation: caves 15/16/17 live in the GUARANTEED-dead P5 ICC
#     body (0x9EE30CA3..0x9EE30D9F) — the region past 0x9EE30DB0 is LIVE
#     code (GART/region-manager family); cave17's original placement broke
#     the boot twice (live fn @0x9EE30FC0 + a skipped 'push rax' — both fixed).
# usage: bash scripts/wp13_build_all.sh
# ============================================================================
set -e
set -o pipefail
cd .
S=./scripts
K=./kit_build

echo "=== [0] WP12 chain (WP7 base + WP9 + MADT + WP11 + WP12), no boot ==="
WP12_NOBOOT=1 bash $S/wp12_build_all.sh "$@" | tail -4

echo "=== [1] WP13 fixes #1..#7 ==="
python3 -u $S/wp13_patch_free_guard.py       | tail -1   # #1
python3 -u $S/wp13_patch_mtxbound.py                      # #2
python3 -u $S/wp13_patch_ctxnull_guard.py    | tail -1   # #3
python3 -u $S/wp13_patch_regnull_abort.py    | tail -1   # #4
python3 -u $S/wp13_patch_mallocnull_guard.py | tail -1   # #5
python3 -u $S/wp13_patch_arraynull_guard.py  | tail -1   # #6
python3 -u $S/wp13_patch_mtxpool_skip.py     | tail -1   # #7

echo "=== [2] WP13 fixes #8..#10 (cave relocation into the P5 dead body) ==="
python3 -u $S/wp13_relocate_caves.py | tail -3           # #8+#9+#10

echo "=== [3] WP13 fixes #11..#17 ==="
python3 -u $S/wp13_patch_allocobj_skip.py    | tail -1   # #11
python3 -u $S/wp13_patch_dispatch_skip.py    | tail -1   # #12
python3 -u $S/wp13_patch_lockclass_skip.py   | tail -1   # #13
python3 -u $S/wp13_patch_linkelf_skip.py                  # #14
python3 -u $S/wp13_patch_linkersym_skip.py               # #15
python3 -u $S/wp13_patch_linkerfile_guard.py | tail -1   # #16
python3 -u $S/wp13_patch_div0_guard.py                   # #17

if [ "$WP13_NOBOOT" = "1" ]; then
  echo "=== [4] SKIPPED verification boot (WP13_NOBOOT) ==="
else
echo "=== [4] verification boot ==="
cd $K && bash run.sh 300 > /dev/null 2>&1 || true
grep -a -m1 "SIE CONFIDENTIAL" serial.log || echo "!! banner missing"
grep -a -m1 "Memory mode" serial.log || echo "!! Memory mode missing"
grep -a -c "can't re-use a leaf" serial.log | xargs echo "sysctl leaf lines:"
grep -a -m1 "instruction pointer" serial.log || echo "(no crash — clean boot!)"
grep -a -m1 "panic:" serial.log || true
wc -l serial.log | xargs echo "serial lines:"
fi
echo "=== WP13 build complete ==="
