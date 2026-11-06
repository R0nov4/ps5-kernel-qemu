#!/bin/bash
# ============================================================================
# WP28 — the tail-walk unblock: G49 M_WAITOK livelock guards + G50 park
# ----------------------------------------------------------------------------
# THE ROUND LAWS (inherited):
#   [0] NO rebuild from scratch — base is the golden WP20 image (81a43724...).
#   [1] Full chain: WP21 (G16..G28) -> WP22 (G29..G38) -> WP23 (G39..G41)
#       -> WP24 (G42) -> WP25 (G43+G44) -> WP26 (G45+G46) -> WP28.
#       The WP27 G48 sweep is DISCARDED (regression: guard above cave48 in
#       0x9e6b6eb0 killed kmem_suballoc -> 'panic: kmem_suballoc: cannot
#       create submap'). Only its G47 hand guard survives (byte-exact,
#       gate-checked against the user-verified laptop image).
#   [2] Intermediate gates: WP22 = 2f821627..., WP23 = f1cedeee...,
#       WP24 = 697f2632..., WP25 = 5d438a93..., WP26 = a822c626...,
#       G47  = 175a002c... (user-verified: zero crashes, 45s quiet).
#   [3] ROOT CAUSE fixed by G49: stage #1296 canvasmap handler mallocs its
#       bitmap with M_WAITOK (0x102) at 0x9edf41d9; the ENOMEM-era wait/
#       retry inside malloc/uma livelocks (GDB @12s: rip=0x9f00a425, the
#       'malloc(M_WAITOK)' sleep-check). G49 downgrades M_WAITOK->M_NOWAIT
#       at 25 tail-only call sites (R1 transparent / R2 epilogue-bail,
#       three static gates per bail, every fn re-audited NOT reachable
#       from stages #0..#1295). G50 adds direct port-0x402 emission of
#       the park string (isa-debugcon -> serial.log) to the G41 stub.
#   [4] FINAL GATE: md5 a7f800301bb9571039aff7ab61ce23b8.
#   [5] ZERO QEMU / ZERO GDB: static capstone + keystone verification only.
#       The boot verification is the user's own test: bash run.sh 240.
# ============================================================================
KIT=$(cd "$(dirname "$0")/.." && pwd)
cd "$KIT" || exit 1
S=$KIT/scripts

echo "=== [0] RESTORE THE GOLDEN WP20 BASE ==="
CUR=$(md5sum wp3_boot/kernel_raw.bin 2>/dev/null | cut -d' ' -f1)
SKIP_TO=""
if [ -f wp20_golden_kernel_raw.bin ]; then
  cp -f wp20_golden_kernel_raw.bin wp3_boot/kernel_raw.bin || exit 1
  [ "$(md5sum wp3_boot/kernel_raw.bin | cut -d' ' -f1)" = "81a437245258e16d9296fb259002f3df" ] \
    || { echo "!! golden base corrupted — aborting"; exit 1; }
  echo "base OK: 81a437245258e16d9296fb259002f3df (WP20 golden)"
elif [ "$CUR" = "a7f800301bb9571039aff7ab61ce23b8" ]; then
  echo "kernel_raw.bin IS the final WP28 image ($CUR) — already built, nothing to do"; exit 0
elif [ "$CUR" = "175a002cf7665ff88bb43a04241a6d95" ]; then
  echo "golden absent — kernel is the G47 image: incremental mode (WP28 step only)"
  SKIP_TO="WP28"
elif [ "$CUR" = "a822c626c50d38a29af2c0a4960d9dae" ]; then
  echo "golden absent — kernel is the WP26 image: incremental mode (G47 + WP28)"
  SKIP_TO="G47"
else
  echo "!! no golden base and kernel is not a known chain image ($CUR) — aborting"; exit 1
fi
if [ -z "$SKIP_TO" ]; then

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
echo "WP22 gate OK: 2f821627fc6f9277b30c0ca9d60b6e5c"

echo "=== [3] THE WP23 CHAIN (G39..G41) ==="
python3 -u $S/wp23_patch_g39_unpark.py       | tail -1
python3 -u $S/wp23_patch_g40_tableguard.py   | tail -1
python3 -u $S/wp23_patch_g41_endpark.py      | tail -1
MD5=$(md5sum wp3_boot/kernel_raw.bin | cut -d' ' -f1)
[ "$MD5" = "f1cedeeefdc7e1cf8ad403b1df8a3575" ] \
  || { echo "!! WP23 gate FAIL ($MD5) — aborting"; exit 1; }
echo "WP23 gate OK: f1cedeeefdc7e1cf8ad403b1df8a3575"

echo "=== [4] THE WP24 GUARD (G42 — NULL-zone accessor family x5) ==="
python3 -u $S/wp24_patch_g42_nullguard.py    | tail -1
MD5=$(md5sum wp3_boot/kernel_raw.bin | cut -d' ' -f1)
[ "$MD5" = "697f263214a4104623bad46a83c75537" ] \
  || { echo "!! WP24 gate FAIL ($MD5) — aborting"; exit 1; }
echo "WP24 gate OK: 697f263214a4104623bad46a83c75537"

echo "=== [5] THE WP25 GUARDS (G43 crash site + G44 sweep x23) ==="
python3 -u $S/wp25_patch_g43_nullguard.py    | tail -2
MD5=$(md5sum wp3_boot/kernel_raw.bin | cut -d' ' -f1)
[ "$MD5" = "3a3913c023ed0ef4a59f3583287cf4d6" ] \
  || { echo "!! G43 gate FAIL ($MD5) — aborting"; exit 1; }
echo "G43 gate OK: 3a3913c023ed0ef4a59f3583287cf4d6"
python3 -u $S/wp25_patch_g44_sweep.py        | tail -3
MD5=$(md5sum wp3_boot/kernel_raw.bin | cut -d' ' -f1)
[ "$MD5" = "5d438a939e327950884e8e97289d18a6" ] \
  || { echo "!! WP25 gate FAIL ($MD5) — aborting"; exit 1; }
echo "WP25 gate OK: 5d438a939e327950884e8e97289d18a6"

echo "=== [6] THE WP26 GUARDS (G45 crossmp + G46 panic sweep x448) ==="
python3 -u $S/wp26_patch_g45_g46.py          | grep -E '^(OK|closure|gate-passed)' | tail -3
MD5=$(md5sum wp3_boot/kernel_raw.bin | cut -d' ' -f1)
[ "$MD5" = "a822c626c50d38a29af2c0a4960d9dae" ] \
  || { echo "!! WP26 gate FAIL ($MD5) — aborting"; exit 1; }
echo "WP26 gate OK: a822c626c50d38a29af2c0a4960d9dae"
fi

if [ -z "$SKIP_TO" ] || [ "$SKIP_TO" = "G47" ]; then
echo "=== [7] THE WP28 G47 (rib-head NULL guard — G48 SWEEP DISCARDED) ==="
python3 -u $S/wp28_patch_g47.py              | grep "^OK" | tail -2
MD5=$(md5sum wp3_boot/kernel_raw.bin | cut -d' ' -f1)
[ "$MD5" = "175a002cf7665ff88bb43a04241a6d95" ] \
  || { echo "!! G47 gate FAIL ($MD5) — aborting"; exit 1; }
echo "G47 gate OK: 175a002cf7665ff88bb43a04241a6d95 (user-verified laptop image)"
fi

echo "=== [8] THE WP28 GUARDS (G49 M_WAITOK livelock x25 + G50 park 0x402) ==="
python3 -u $S/wp28_patch_g49_g50.py          | grep -E "^(OK|\[gates\]|\[audit\]|  SKIP)" | tail -6

echo "=== [9] THE FINAL BYTE-EXACT GATE ==="
SZ=$(stat -c%s wp3_boot/kernel_raw.bin)
echo "kernel_raw.bin size: $SZ"
[ "$SZ" = "65224704" ] || { echo "!! SIZE MISMATCH — aborting"; exit 1; }
MD5=$(md5sum wp3_boot/kernel_raw.bin | cut -d' ' -f1)
echo "kernel_raw.bin md5: $MD5"
[ "$MD5" = "a7f800301bb9571039aff7ab61ce23b8" ] \
  || { echo "!! NOT BYTE-EXACT (expected a7f800301bb9571039aff7ab61ce23b8) — aborting"; exit 1; }
echo ">>> WP28 IMAGE OK — G47 + G49(x25, tail-only, early-audited) + G50 (zero QEMU) <<<"
echo ">>> boot it yourself: bash run.sh 240 — march on to 'WP23: sysinit walk complete; parking.' <<<"
