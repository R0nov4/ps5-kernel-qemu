#!/bin/bash
# ============================================================================
# WP23 — THE FINAL MARCH: the 95 post-landmark sysinit entries (1141..1235)
# ----------------------------------------------------------------------------
# THE ROUND LAWS (the user's iron directives, inherited):
#   [0] NO wp16_build_all.sh from scratch — the base is the golden WP20
#       image shipped in the kit (wp20_golden_kernel_raw.bin, md5
#       81a437245258e16d9296fb259002f3df). NO QEMU, NO GDB in this script.
#   [1] Full chain: WP21 (13 scripts, G16..G28) -> WP22 (10 scripts,
#       G29..G38) -> WP23 (3 scripts, G39..G41). All idempotent.
#   [2] Intermediate gate after WP22: md5 2f821627fc6f9277b30c0ca9d60b6e5c
#       (the delivered boot-verified landmark image).
#   [3] FINAL GATE: md5 f1cedeeefdc7e1cf8ad403b1df8a3575 (the WP23 image:
#       unparked + trie-block-guarded + end-of-walk-parked).
#   [4] ZERO QEMU / ZERO GDB in this round (the anti-timeout law): every
#       hook, stub, slot and string was verified statically with capstone
#       (scripts/wp23_verify.py). The boot verification is the user's own
#       test on their laptop: bash run.sh 240 — expected terminal line:
#       'WP23: sysinit walk complete; parking.' with zero crash lines.
# ============================================================================
KIT=$(cd "$(dirname "$0")/.." && pwd)
cd "$KIT" || exit 1
S=$KIT/scripts

echo "=== [0] RESTORE THE GOLDEN WP20 BASE ==="
cp -f wp20_golden_kernel_raw.bin wp3_boot/kernel_raw.bin || exit 1
[ "$(md5sum wp3_boot/kernel_raw.bin | cut -d' ' -f1)" = "81a437245258e16d9296fb259002f3df" ] \
  || { echo "!! golden base corrupted — aborting"; exit 1; }
echo "base OK: 81a437245258e16d9296fb259002f3df (WP20 golden)"

echo "=== [1] THE WP21 CHAIN (G16..G28) ==="
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

echo "=== [2] THE WP22 CHAIN (G29..G38) ==="
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
MD5=$(md5sum wp3_boot/kernel_raw.bin | cut -d' ' -f1)
[ "$MD5" = "2f821627fc6f9277b30c0ca9d60b6e5c" ] \
  || { echo "!! WP22 gate FAIL ($MD5) — aborting"; exit 1; }
echo "WP22 gate OK: 2f821627fc6f9277b30c0ca9d60b6e5c (the landmark image)"

echo "=== [3] THE WP23 CHAIN (G39..G41 — no QEMU, static-verified) ==="
python3 -u $S/wp23_patch_g39_unpark.py       | tail -1
python3 -u $S/wp23_patch_g40_tableguard.py   | tail -1
python3 -u $S/wp23_patch_g41_endpark.py      | tail -1

echo "=== [4] THE FINAL BYTE-EXACT GATE ==="
SZ=$(stat -c%s wp3_boot/kernel_raw.bin)
echo "kernel_raw.bin size: $SZ"
[ "$SZ" = "65224704" ] || { echo "!! SIZE MISMATCH — aborting"; exit 1; }
MD5=$(md5sum wp3_boot/kernel_raw.bin | cut -d' ' -f1)
echo "kernel_raw.bin md5: $MD5"
[ "$MD5" = "f1cedeeefdc7e1cf8ad403b1df8a3575" ] \
  || { echo "!! NOT BYTE-EXACT (expected f1cedeeefdc7e1cf8ad403b1df8a3575) — aborting"; exit 1; }
echo ">>> WP23 IMAGE OK — unparked + guarded + end-parked (zero QEMU this round) <<<"
echo ">>> boot it yourself: bash run.sh 240 — expect 'WP23: sysinit walk complete; parking.' <<<"
