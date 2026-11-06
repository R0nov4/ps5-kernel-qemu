# WP3-STEP 1: pmap_bootstrap (0xffffffff9eccbf50) — Loader Initial-Page-Table Contract

## 1. Physical memory consumption above physfree

Allocation sequence (byte-exact, live-verified):
```
physfree_in  = 0x22225000            (loader arg, 4K page after metadata page)
  + dpcpu_kstack [0x22225000, 0x22229000) 16KB (machine_init, bzero+template)
  → physfree = align64k(physfree + 0xffff) = 0x22230000
PT region   = [0x22230000, 0x24261000)   ← [0xa1f37ed0], npages=0x2031 ([0xa1f37ee0])
               0x2031 × 4KB = 33,554,432 B (33.6 MB) of page-table pages
pv/pt-desc  = [0x24261000, 0x24261000+0x2031*0x30) = [0x24261000, 0x242C1930)
               0x30-byte structs × 8241 (248 KB)
PML4 (CR3)  = 0x22244000               ← [0xa1f37e60] (inside PT region, from region walk)
physfree_out≈ 0x242C4000 (round16k(0x24261000 + 0x60930))
```
npages = ceil(Maxmem/2MB) + ceil(Maxmem/1GB) + ceil(Maxmem/512GB) + 0x20  (0x2031 live)
**TOTAL: ~0x2092000 (33.9 MB) above physfree.** Our loader must reserve RAM up to 0x242D0000.

## 2. Virtual access modes BEFORE the CR3 switch (0x9ecccf03)

The new PT pages are touched through THREE different VA spaces while still running
on the LOADER's initial tables:
1. **IDENTITY (VA = PA)**: `bzero(0x22230000, 0x2031000)` @0x9eccc1dc — the PT
   region itself is zeroed through the low identity map.
2. **DMAP**: `bzero(DMAP(0x24261000), 0x60930)` @0x9eccc230 — the pv/pt-desc array
   is zeroed through the direct map. DMAP(phys) = 0xffff800000000000 | (d39<<39) | (d30<<30) + phys
   (live: d39=0x11c, d30=0x1dc → base **0xffff8e7700000000**; formula verified
   byte-exact against live [0xa1f37eb8] = 0xffff8e7724261000).
3. **KVA window (slot 0x1FF)**: kernel code/data + bootstack — KVA = 0xFFFFFFFF80000000 + PA
   (verified: virtual_avail = 0xFFFFFFFF80000000 + physfree = 0xffffffffa2225000 = live [0xa1978cd0]).

CR3 loaded at 0x9ecccf03 from [0xa1f37e60] (=0x22244000); CR4.PGE/PCIDE setup around it.
The pointers [0xa1f37e38]/[0xa1f38fe0] (recursive-VA of PTE groups) are computed AFTER
the switch → the memmap-builder's later `mov [rax],0` + CR3-flush (0x9edf9c8e) tears
down one temp mapping via the RECURSIVE slot (self-ref PML4 entry) — no loader coverage needed.

## 3. The recursive PML4 slot & DMAP window constants

pmap_bootstrap picks them either from an HV param-chain (SHA-1-ish reads w/ retry loops)
or from a DEFAULT branch (0x9eccc016: slot=0x100, d39=0x1fe, d30=0) gated by two checks:
  gate_A 0x9e995130 (config byte [0x9fe4c064]&4 → memcpy [0x9fe4c088] → bit2)
  gate_B 0x9eebc9a0(0xc) (bitmap [0xa20b1390] bit)
**BOOT POLICY: force the default branch (NOP the two `je` @0x9eccc006/0x9eccc014) and
edit its immediates to the LIVE values: slot=0x18c, d39=0x11c, d30=0x1dc.**
Rationale: the live .data is full of stale pointers computed with the live DMAP base
(UART regs VA 0xffff8e77c1010100, tty 0xffff8e7701906c38, log buf 0xffff8e7b7f2fffb8,
[0xa1f37eb8] …). Using the same constants keeps every baked-in pointer consistent.
NOTE: 0x9eaca400 (boot-param reader, called by machine_init BEFORE pmap_bootstrap) already
computes its DMAP VAs from [0xa1f39294]/[0xa1f39298] — the image values (0x11c/0x1dc) —
so the loader MUST map the DMAP window at 0xffff8e7700000000 from the very beginning.

## 4. 16KB logical pages = 4 × 4KB HW pages

PTE-group addressing: `(VA >> 9) & 0x7fffffffe0` — the byte offset of the 4-aligned
4K-PTE group for the 16K page containing VA. Confirms PS5 kernel PAGE_SIZE=0x4000 built
from 4 consecutive 4K HW PTEs. PT pages themselves are 4KB (`shl r14, 0xc`).

## 5. LOADER INITIAL PAGE TABLES — REQUIRED COVERAGE (pre-CR3-switch)

| VA window                          | → phys            | user                          |
|------------------------------------|-------------------|-------------------------------|
| [0, 0x40000000) identity (slot 0)  | same              | phys params 0x9b000, 0x472, PT bzero 0x22230000..0x24261000, pv array |
| [0xFFFFFFFF80000000, +1GB) (slot 0x1FF) | +0 (KVA)     | kernel image, bootstack 0xa1131000, metadata KVA 0xa2224000 |
| [0xffff8e7700000000, +1GB) (DMAP)  | +0 (DMAP)         | boot-param reads phys 0x9b000-0x9c000 via DMAP, pv-array bzero/walk |

All three windows map phys [0, 0x40000000) with 2MB large pages (RW, present, no NX for
text safety). Post-switch (0x9ecccf03) the kernel runs on its own tables (KVA window +
DMAP + recursive slot are all rebuilt by pmap_bootstrap itself).

## 6. machine_init → memmap-builder flow (context of user's sites)
- 0x9edf951a: call 0x9eaca400 (boot-param reader; reads phys 0x9b000-0x9c000 VIA DMAP,
  copies to .data param cache 0xa1d0ae40..f0; also sets console mute byte from config
  [0x9fe4c15a] — see WP3-STEP2)
- 0x9edf9545: lea rdi,[rbp-0x218] (local physfree) → 0x9edf954c: call pmap_bootstrap
- 0x9edf9551-58f: getenv 'dcons.addr'/'dcons.size' (kern_env from preload metadata;
  on failure dcons_addr=0 → no reservation)
- 0x9edf9596: wrmsr 0x1D9 (IA32_DEBUGCTL = 1 → LBR enable — the reason LBR MSRs matter)
- 0x9edf992a: rcx = [0xa1f38fe0] (recursive-VA PTE ptr, live 0xffffc67fffd33020)
- 0x9edf9958: printf('Testing system memory') — loop touches only .data/stack
- 0x9edf9c8e: mov qword [rax], 0 + CR3 reload — tears down the temp KVA window page
  (recursive-slot access on the NEW tables; happens AFTER pmap_bootstrap switched CR3)
