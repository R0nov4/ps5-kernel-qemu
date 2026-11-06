#!/usr/bin/env python3
"""WP2 STEP 2 — deliverable: .data/.bss boundary + Live State Sanitization report."""
import json

OUT = "./download/ps5_wp2"

REP = r"""
====================================================================================================
WP2-STEP2 — .data/.bss BOUNDARY + LIVE-STATE SANITIZATION (13.60 dump)
====================================================================================================

KEY GEOMETRIC FACT (established in Step 1, changes everything):
  The dumped "kernel_data" [0xffffffff9f0b0000, 0xffffffffa46b0000) (90.2MB) is the kernel's
  full data MAPPING, but the actual ELF IMAGE is only:
      .text        [0xffffffff9e3f0000, 0xffffffff9f0b0000)   0xCC0000  (13.4 MB)
      .data+.bss   [0xffffffff9f0b0000, 0xffffffffa2224000)   0x3174000 (49.4 MB)
  image end = preload-metadata start = 0xffffffffa2224000 (modulep 0x22224000; physfree
  0x22225000 = modulep + 0x1000 — byte-verified from live virtual_avail/td_kstack).
  Everything in the dump ABOVE 0xa2224000 (~38.5MB) is RUNTIME KERNEL HEAP (vmem/kmem
  allocations) — it is NOT part of the kernel image and is EXCLUDED from the
  reconstructed ELF.

================================================================================
Q2-a) IS .bss SEPARABLE?
================================================================================
EMPIRICAL DENSITY PROFILE of the image data range (16KB-page granularity, live dump):

  [0x9f0b0000, 0x9f4b0000)   ~60% nonzero, contains a 1.5MB pure-zero run
                              (0x9f28c000-0x9f408000)         -> .rodata + zero tables
  [0x9f4b0000, 0xa04b0000)   90-100% nonzero — DENSE          -> .rodata/.data CORE
                              (strings 'elf kernel'@0x9f6faa23 etc., linker sets
                               sysinit_set@0x9fe51fb0, sysuninit_set@0x9fe55070,
                               dpcpu template@[0x9fe5a080,0x9fe5add0))
  [0xa04b0000, 0xa2224000)   3-30% nonzero — SPARSE           -> .data (sparse static
                              initializers: mutexes, sysctl OIDs...) mixed with .bss
  Longest untouched all-zero runs INSIDE the image (pure .bss, never written since boot):
      [0xa1318000, 0xa1838000)   5.2 MB
      [0xa0510000, 0xa05d8000)   800 KB
      [0xa1fe8000, 0xa20b0000)   800 KB   (right before image end!)
      [0xa1ae4000, 0xa1ba4000)   768 KB, + ~10 more runs of 240-576KB

VERDICT: the .data/.bss line is NOT byte-exact separable from the dump alone (it needs the
original ELF section headers): initialized-.data islands (GDT source table @0xa0955ad0,
boot-svc table @0xa0955a28..48, sparse sysctl/mtx objects) are scattered INSIDE the
sparse zone all the way up to the image end, interleaved with .bss arrays.
ENGINEERING ANSWER: we do NOT need the exact line. The Reconstructor emits the whole image
data range as ONE .data PROGBITS segment (live bytes + surgical patches below) and CUTS
the segment at 0xa2224000. The 1586 re-executed sysinit stages rebuild all .bss-class state;
the only state that must be surgically corrected is enumerated below.

================================================================================
Q2-b) IF WE ZERO .bss — DO WE WIPE LOADER-BUILT CRITICAL TABLES?
================================================================================
  * INITIAL PAGE TABLES: NOT IN THE KERNEL IMAGE AT ALL. The Sony loader builds them
    outside the image (kernel consumes KERNBASE+phys mapping + low-phys identity map;
    machine_init reads loader metadata through them). Zeroing .bss cannot touch them.
    (For QEMU: OUR loader builds them — see Loader Contract.)
    => SAFE.
  * GDT: TWO components.
      - static 13x18B SOURCE table @0xa0955ad0 (INITIALIZED .data — never zeroed);
      - live GDT @0xa1fa55e0 — REBUILT from the source table at EVERY machine_init
        (loop @0x9edf8915..89c2; GDTR {limit 0x67, base 0xa1fa55e0} @0xa1fa89e0;
         lgdt + full segment reload + retfq CS=0x20 in 0x9e649a50).
    => ZEROING IS SAFE (even if the live GDT area were zeroed, it is rebuilt first).
  * IDT @0xa1fa4300: ALL 256 gates rewritten at every machine_init (fill loop
    0x9edf8c10..0x9edf8c24 + ~30 specific gates), then lidt via pseudo-desc @0xa1fa8a50.
    => ZEROING IS SAFE.
  * TSS @0xa1fa6fe0 + TSS descriptor (GDT entry 9, selector 0x48): rebuilt; ltr at every
    machine_init. => SAFE.
  * per-CPU area @0xa1fb8f00: bzero(0x980) + dpcpu template copy EVERY machine_init
    (0x9e8b8150/0x9e8b81d0). => SAFE.
  * Giant/'blocked lock'/'icu'/'descriptor tables'/'wbinvd'/'l2idsm': mtx_init re-run at
    every machine_init. => SAFE.
  * proc0/thread0/vmspace0 statics: re-initialized (0x9ef80000 + stack chain).
  => CONCLUSION: full .bss zeroing is SAFE for every loader-built/critical table.
     The ONLY .data the kernel needs intact pre-boot is the Step-1 cold-input list
     (boot-svc table, GDT source, dpcpu template, linker symbols, tunable defaults).

================================================================================
Q2-c) LIVE-STATE SANITIZATION LIST (what must return to Cold-Boot state)
================================================================================
1. mi_startup re-entrancy bookkeeping (0xa1978190..0xa19781b0 block):
      boothowto    @0xa1978190 : live 0x20001000 — HARDCODED by cpu-init hook at boot
                                  (0x9edf6ab1) => NO PATCH NEEDED (rewritten every boot)
      aux2         @0xa1978198 : live 0          -> 0
      aux1         @0xa19781a0 : live 0          -> 0
      end          @0xa19781a8 : live 0xffffffff9fe54650 (residue of COMPLETED boot,
                                 = last real entry before Sony-dummy block at slot 1239)
                                 -> 0
      being_run    @0xa19781b0 : live 0xffffffff9fe51fb0 (= sysinit_set start — residue)
                                 -> 0
   (previous session's 'mid re-run window' interpretation corrected: these are the
    POST-COMPLETION residues of a normal boot; mi_startup rewrites them itself.)
2. sysinit entry stamps: si_sub==1 (SI_SUB_DONE) on 1586 entries -> Step-3 recipe.
3. HELD MUTEXES AT DUMP TIME (strict scan, owner-thread validation):
      struct mtx layout (Sony, 0x20B, derived from mtx_init 0x9e8b7dd0):
         +0x00 lo_name (char*), +0x08 lo_flags, +0x0C recurse(u32),
         +0x10 witness/other, +0x18 mtx_lock — 4 == FREE, owner|flags == HELD
      scan result over image range: 8616 mtx-like objects =>
         7792 FREE (lock==4 — already the correct cold value)
          811 ZERO (lock==0 — pre-mtx_init state, also fine)
           13 HELD  (must be reset to 4; recurse to 0):
      'Sysctl internal magic'      @0xa095a370  owner 0xffffffffa197a5a0
      'File system'                @0xa095a3d0  owner 0xffffffffa197a5a0
      'Sizeof various things'      @0xa095a4f0  owner 0xffffffffa197a5a0
      'hardware'                   @0xa095a550  owner 0xffffffffa197a5a0
      'user-level'                 @0xa095a5b0  owner 0xffffffffa197a5a0
      'machine dependent'          @0xa095c4a0  owner 0xffffffffa197a5a0   (6 sysctl
                                    tree locks — held by the sysctl-walking thread at
                                    dump time; all re-initialized by sysinit stages)
      'pfs'                        @0x9fe6a568  owner 0xffffffffa1f70030
      'savedata'                   @0x9fe6a598  owner 0xffffffffa1f70038
      'devfs dirlist lock'         @0x9febef08  owner 0xffffffffa1964000
      'Enable event timer periodic mode' @0xa05f89a0 owner 0xffffffffa1d8da90
      'ACPI root bus'              @0xa0fe86c8  owner 0xffffffffa2187830
      'audit_watermark_cv'         @0xa18c18f8  (condvar-struct false-positive-ish)
      'mbus_cv'                    @0xa1d0c488  (condvar-struct false-positive-ish)
      => RECONSTRUCTOR ACTION: write 4 to [base+0x18] and 0 to [base+0xC] for the 11
         true mutexes (belt-and-braces — their MTX_SYSINIT stages also re-init them).
4. HIGH-REF FLAG WATCHLIST (boot-critical boolean candidates; most-referenced
   cmp-with-zero dwords):
      0xa1978858  (259 refs, live 0) — sits immediately before thread0 in the
                  init_main.c globals block; checked before the 'basemem' verbose
                  print; top candidate for 'cold'/'bootverbose' — see Step-3a for
                  the mi_startup writer analysis (mi_startup writes it at its tail).
      0xa199e9d8  (329 refs, live 0) — ACPI sci-trigger related (writer found in
                  acpi code) — NOT boot-critical.
      0xa197818c  (69 refs, live 0) — kern_shutdown.c flag (shutdown path).
      0xa09135d0  (88 refs, live 1), 0xa10a0000 (82 refs, live 0),
      0xa20b2c90  (70 refs, live 0 — usbc_ctrl state) — subsystem state, re-inited.
5. Everything else: the 1586 sysinit stages ARE the cold-boot initialization code —
   re-running them in the exact original order (Step 3) re-initializes all subsystem
   state (locks, pools, lists, caches) the same way a real cold boot does.

RESIDUAL RISK NOTE (honest engineering):
  Runtime-flipped one-shot flags in .data whose cold value differs from the live value
  AND which are read before their re-initializing stage are the only theoretical
  hazard; the watchlist above covers the highest-signal candidates; boothowto and the
  machine_init path are already proven self-healing. The mi_startup tail analysis
  (Step-3a) resolves the 'cold'-flag candidate definitively.
================================================================================
"""

with open(f"{OUT}/wp2_2_bss_sanitization.txt", "w") as f:
    f.write(REP.lstrip("\n"))

js = {
  "image_geometry": {
    "text": "[0xffffffff9e3f0000, 0xffffffff9f0b0000) 0xCC0000",
    "data_bss_image": "[0xffffffff9f0b0000, 0xffffffffa2224000) 0x3174000",
    "image_end": "0xffffffffa2224000 (= preload metadata start)",
    "runtime_heap_excluded": "[0xffffffffa2224000, 0xffffffffa46b0000) ~38.5MB"
  },
  "bss_separable": "not byte-exact; single-PROGBITS .data + surgical patches strategy",
  "zeroing_bss_safe_for": ["page tables (not in image)", "GDT (rebuilt from source@0xa0955ad0)",
                            "IDT (256 gates rebuilt)", "TSS", "pcpu (bzero+template)", "early mutexes"],
  "sanitization_patches": {
    "mi_globals": {"0xffffffffa1978198": 0, "0xffffffffa19781a0": 0,
                    "0xffffffffa19781a8": 0, "0xffffffffa19781b0": 0},
    "held_mutexes_reset_to_4": [
      "0xffffffff9fe6a568 pfs", "0xffffffff9fe6a598 savedata",
      "0xffffffff9febef08 devfs dirlist lock", "0xffffffffa05f89a0 event timer periodic",
      "0xffffffffa095a370 Sysctl internal magic", "0xffffffffa095a3d0 File system",
      "0xffffffffa095a4f0 Sizeof various things", "0xffffffffa095a550 hardware",
      "0xffffffffa095a5b0 user-level", "0xffffffffa095c4a0 machine dependent",
      "0xffffffffa0fe86c8 ACPI root bus"
    ],
    "mtx_layout": "+0x00 name, +0x08 lo_flags, +0x0C recurse, +0x18 mtx_lock (4=free)"
  }
}
with open(f"{OUT}/wp2_2_sanitization.json", "w") as f:
    json.dump(js, f, indent=1)
print(f"wrote {OUT}/wp2_2_bss_sanitization.txt")
print(f"wrote {OUT}/wp2_2_sanitization.json")
