#!/bin/bash
# ============================================================================
# WP17 — full reproducible build of the PS5 13.60 boot kit
# pristine WP7 base -> WP12 chain -> WP13 chain -> WP14 chain -> WP15 chain
#   -> WP16 chain (20 fixes)
#   + WP17 (18 fixes — the Zone/Chunk family + the malloc machinery +
#            the systemic seeds + the window extension):
#       #1  zone-drain entry guard (cave63 @0x9E401880)
#           crash 0xffffffff9e82b788 CR2=0x98: the post-APIC hashinit-style
#           1MB malloc's large path -> the fill failed -> the drain with
#           the NULL zone-table global [0xa18ea8c0] -> 'mov r15,[rdi+0x98]'
#           -> rdi = 0. The guard: rdi==0 -> plain ret at the entry
#           (nothing modified — clean for all 8 callers; the chunk leaks).
#       #2  hook3 NULL-symmetry (cave64 @0x9E401900)
#           the drain's hook3 [zone+0xb8] is the ONLY hook without a
#           designed NULL check (validated against the 20-slot thunk
#           array, fail -> warn -> call NULL). NULL -> skip to the
#           balance check — the designed hook1/hook2 semantics.
#       #3  THE SYSTEMIC ZONE-TABLE SEED
#           [0xa18ea8c0] := DMAP(0x3F1A0880) — a pristine-zero page in
#           the seed-area scratch gap: hooks NULL (designed skips),
#           import NULL (cave56's bump), +0x110 the harmless lock-add.
#           The whole 0x9e82bxxx family reads valid memory.
#       #4  kmem arena extend-thunk read-time fallback (cave65 @0x9E401980)
#           the 0xF4000 (1MB) kmem alloc's slow path: [arena+0x428] ==
#           NULL (the arena struct wiped by a later SYSINIT after WP16#15
#           seeded it) -> the wait-fail. The fallback: NULL -> the WP14
#           thunk 0x9E65BF80 (a VALID slot) -> the designed validation
#           legitimizes it -> the pool serves (14MB, self-healing).
#       #5  W1 v3 — the vm_page supply extension (cave66 @0x9E401A00)
#           with the kmem VA succeeding, the fill loop's populate part
#           calls vm_page_alloc per 16KB page — the W1 bump's 896KB
#           region exhausted since vm_page_startup's 2GB walk. v3: the
#           pool-carved 1MB extension slices (pool-next @0x3F004008,
#           ext-base @0x3F1A0840, floor 0x3FF00000, [obj+0x30]=own-phys).
#       #6  THE MALLOC BUMP WINDOW EXTENSION (caves 50/56/51 imms)
#           0x3F200000 -> 0x3F740000: the window [0x3F1A1000, 0x3F740000)
#           = 5.6MB (a 14.7x extension; spans the user's [0x3F500000..)
#           while staying clear of the WP14 node chains @0x3F740000+ and
#           the extent pool — no collisions by construction).
#       #7  cave57 exit retarget (the double-unlock)
#           'panic: __mtx_unlock_flags: td_locks -1': WP16#15's cave57
#           jumped to 0x9e9d7066 (the TAIL unlock) but the wait-fail
#           path already unlocked at 0x9e9d7028 -> unlock TWICE per
#           iteration. Retarget: 0x9e9d7001 (the lock-released exit).
#       #8  kmem-arena lazy bootstrap (cave67 @0x9E401B00)
#           the arena's node cache [arena+0x408] = NULL (cave22 only
#           treated the 3 STATIC arenas): carve 64KB from the pool +
#           build the 1024-node chain (cave22's exact list format) +
#           the count/hash/thunk/anchor fields — the same treatment the
#           static arenas get, applied lazily to any empty arena.
#       #9  THE SYSCTL OID-TREE PARENT SEED (9 links)
#           crash 0xffffffff9e946a00 CR2=0x34: the OID path-walker
#           (0x9e9467c0) walks [obj+8] parents to the root 0xa197a5a0 —
#           the static top branches 'vfs'/'net'/'hw'/'user'/'p1003_1b'/
#           'kern' (+3 more) carry live-residue parents (=4) where the
#           live dump holds the designed links. Image-seeded.
#       #10 OID path-walker loop-head guard (cave68 @0x9E401C00)
#           rbx (the element) == 0 or < 0x10000 -> the loop's done point
#           (the belt & braces for any remaining residue).
#       #11 zone-import failure bump (cave69 @0x9E401C80)
#           the zone-create flow's real import (0x9e82b2c3 'call r12')
#           returns eax=0 on every retry (the never-initialized supply)
#           -> the designed fail -> NULL -> 'mov [rax],-1' at 0x9ec2d09c
#           writes [NULL]. The fail branch -> the SHARED bump + cave56's
#           return tail.
#       #12 panic-path NULL-device guard (cave70 @0x9E401D00)
#           the 119x recursive 'panic during panic' spiral: the dump
#           machinery's device capability read 'mov rcx,[rdi+0x80]'
#           with rdi=NULL -> re-trap inside the panic -> ~95KB of stack
#           burned. NULL -> return 0 (the 'no capabilities' answer).
#       #13 configure-accessor NULL-lock-container guard (cave71 @0x9E401D80)
#           crash 0xffffffff9e8b6a2d CR2=0x18: the sysctl-leaf ctx's
#           [obj+0x40] (the lock container) = NULL on the fresh bump
#           object -> mtx_lock(0x18). NULL -> the void skip.
#       #14 zone-bucket-slot plausibility guard (cave72 @0x9E401E00)
#           crash 0xffffffff9e82b933 CR2=0xbe4b47: the static zone's
#           bucket slot holds the pristine non-pointer pair {0xffffffff,
#           0xbe4b37} (the designed buckets are runtime objects). The
#           walk head: implausible values (bits 63..48 != 0xffff) ->
#           sanitized to the designed empty/recycle paths.
#       #15 zone-lookup validation (cave73 @0x9E401E80)
#           the jump-to-a-string crash (IP=0x9f6f4b2f): the malloc
#           TYPE's zone-table = a ZERO bump page -> the static class
#           array answers with non-zone .data (the 'TSC-low' timer with
#           string hook-fields; a MISALIGNED 0xa0fee5b4 whose [zone+0x40]
#           = 0x9e65cf5000000000 -> the non-canonical lock -> GPF).
#           The loaded zone must be: non-NULL, 8-aligned, canonical, and
#           its [+0xb0] NULL-or-thunk ([0x9E650000,0x9E660000)) — else
#           NULL (the malloc NULL flow). WP12's cave7 already guards the
#           bucket-alloc entry (verified, reused).
#       #16 malloc bucket-NULL bump (cave75 @0x9E401F80)
#           the return of crash 0x9e9471ad CR2=0x8: with the validated
#           lookups the bucket alloc returns NULL cleanly but the
#           continuation never reaches the designed malloc-NULL node
#           (cave11's path needs a NULL TYPE-table) -> the caller writes
#           [NULL+8]. The NULL branch -> the SHARED bump (cave50's
#           window) -> r14/rax := the object.
#       #17 thread0 WITNESS head seed + reset-reseed + NULL-preserving
#           store (cave76 @0x9E402000 + cave77 @0x9E402080)
#           crash 0xffffffff9e8b71bc CR2=0x18: [thread0+0x78] = NULL
#           (the witness allocation never ran). The seed: DMAP(0x3F1A0A00)
#           (a zero page); the witness-reset wipe (0x9e81d12e) -> the
#           reseed (the cave writes the seed instead of 0); the designed
#           allocation store (0x9e81e595) -> NULL results keep the seed.
#       #18 witness list-append NULL-tail guard (cave78 @0x9E402100)
#           crash 0xffffffff9e81d943 CR2=0x0: the empty list's append
#           '[rdx] = rbx' with the NULL tail. Skipping the tail store
#           leaves a valid single-element list (the end marker NULL).
#       #19 witness owner-list plausibility guard (cave79 @0x9E402180)
#           crash 0xffffffff9e81d975 GPF: the owner-list link reads
#           [r13+0x128] = a non-canonical garbage -> 'mov [rax+0x68],rcx'
#           -> #GP. Implausible -> skip the owner-list stores.
# BOOT PROGRESS (the verification): past the 1MB hash-table alloc, the
#   MADT/SMP enumeration ('SMP: Added CPU 0..7'), the PIR/MPTABLE/SMBIOS
#   copies, the ACPI DSDT parse, ~999 sysctl leaves — the frontier is
#   now the witness/lock-graph bookkeeping family (0x9e81dxxx).
# usage: bash scripts/wp17_build_all.sh
# ============================================================================
set -e
set -o pipefail
cd .
S=./scripts
K=./kit_build

echo "=== [0] WP16 chain (WP7 base + ... + WP16, incl. its verification boot) ==="
bash $S/wp16_build_all.sh "$@" | tail -3

echo "=== [1] WP17 #1/#2/#3 zone-drain guard (cave63) + hook3 NULL-symmetry (cave64) + the zone seed ==="
python3 -u $S/wp17_patch_zonedrain_guard.py | tail -2
echo "=== [2] WP17 #4 kmem thunk fallback (cave65) ==="
python3 -u $S/wp17_patch_kmem_thunk.py | tail -1
echo "=== [3] WP17 #5 W1 v3 vm_page supply extension (cave66) ==="
python3 -u $S/wp17_patch_w1_extend.py | tail -1
echo "=== [4] WP17 #6 malloc bump window 380KB -> 5.6MB (caves 50/56/51) ==="
python3 -u $S/wp17_patch_malloc_window.py | tail -2
echo "=== [5] WP17 #7 cave57 exit retarget (the td_locks double-unlock) ==="
python3 -u $S/wp17_patch_cave57_retarget.py | tail -1
echo "=== [6] WP17 #8 kmem-arena lazy bootstrap (cave67) ==="
python3 -u $S/wp17_patch_kmem_arena_boot.py | tail -1
echo "=== [7] WP17 #9 sysctl OID-tree parent seed (9 links) ==="
python3 -u $S/wp17_patch_oid_parent_seed.py | tail -1
echo "=== [8] WP17 #10 OID path-walker guard (cave68) ==="
python3 -u $S/wp17_patch_oidwalk_guard.py | tail -1
echo "=== [9] WP17 #11 zone-import failure bump (cave69) ==="
python3 -u $S/wp17_patch_import_bump.py | tail -1
echo "=== [10] WP17 #12 panic-path NULL-device guard (cave70) ==="
python3 -u $S/wp17_patch_panicpath_guard.py | tail -1
echo "=== [11] WP17 #13 configure NULL-lock guard (cave71) ==="
python3 -u $S/wp17_patch_configure_guard.py | tail -1
echo "=== [12] WP17 #14 bucket-slot plausibility guard (cave72) ==="
python3 -u $S/wp17_patch_bucket_plausibility.py | tail -1
echo "=== [13] WP17 #15 zone-lookup validation (cave73) ==="
python3 -u $S/wp17_patch_zonelookup_valid.py | tail -1
echo "=== [14] WP17 #16 malloc bucket-NULL bump (cave75) ==="
python3 -u $S/wp17_patch_malloc_null_bump.py | tail -1
echo "=== [15] WP17 #17 thread0 witness seed + cave76/77 ==="
python3 -u $S/wp17_patch_thread0_witness.py | tail -1
python3 -u $S/wp17_patch_witness_reset.py | tail -1
python3 -u $S/wp17_patch_witness_alloc.py | tail -1
echo "=== [16] WP17 #18 witness append NULL-tail guard (cave78) ==="
python3 -u $S/wp17_patch_witness_append.py | tail -1
echo "=== [16b] WP17 #19 witness owner-list plausibility guard (cave79) ==="
python3 -u $S/wp17_patch_witness_owner.py | tail -1

echo "=== [17] size sanity (must equal pristine 65224704) ==="
SZ=$(stat -c%s $K/wp3_boot/kernel_raw.bin)
echo "kernel_raw.bin size: $SZ"
[ "$SZ" = "65224704" ] || { echo "!! SIZE MISMATCH — aborting"; exit 1; }

echo "=== [18] verification boot ==="
cd $K && bash run.sh 300 > /dev/null 2>&1 || true
grep -a -m1 "SIE CONFIDENTIAL" serial.log || echo "!! banner missing"
grep -a -m1 "Memory mode" serial.log || echo "!! Memory mode missing"
grep -a -c "can't re-use a leaf" serial.log | xargs echo "sysctl leaf lines:"
grep -a -m1 "Event timer" serial.log || echo "!! Event timer missing"
grep -a -m1 "ACPI APIC Table" serial.log || echo "!! ACPI table missing"
grep -a -m1 "Multiprocessor System" serial.log || echo "!! SMP missing"
grep -a -m1 "SMP: Added CPU 7" serial.log || echo "!! SMP AP-add missing"
grep -a -m1 "parse DSDT" serial.log || echo "!! DSDT missing"
grep -a -m1 "panic:" serial.log || true
grep -a -m1 "instruction pointer" serial.log || echo "(no crash — clean boot!)"
wc -l serial.log | xargs echo "serial lines:"
echo "=== WP17 build complete ==="
