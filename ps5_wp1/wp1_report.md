# WP1 — PS5 13.60 Kernel: HV Hypercall ABI + MSR Map + Entry/SysInit

Source: terrafirma2021/ps5-13.60-kernel-dump (SHA-256 verified). All findings byte-verified in this dump; no guesswork — semantics derived from
the kernel's own panic/log strings, `__FILE__` paths and linker sets.

## 1. Sony HV Hypercall ABI (kernel side)

- Mechanism: `vmmcall` (0F 01 D9), hypercall number in **EAX**, args in SysV-AMD64
  registers (some wrappers marshal into **RBX/EBX** — non-SysV), return in EAX/RBX/RDX/RDI/RSI.
- Implementation: `sys/kern/kern_hv.c` (build path `W:/Build/J03950001/sys/freebsd/sys/kern/kern_hv.c`).
- 26 wrapper functions, 33 vmmcall sites, all inside region 0x9f006a10..0x9f00720d (+ tails).
- Xrefs: 53 direct call/jmp (all back-sweep verified), 1 data pointer, 0 lea/absolute (wrappers are only called directly).

| # | EAX | wrapper | size | ABI (marshal before vmmcall) | callers | evidence (kernel strings) |
|---|-----|---------|------|------------------------------|---------|---------------------------|
| ffffffff9f006a10 | 0x4 | 0xffffffff9f006a10 | 14B | pure passthrough | 2 fn(s) from 0xffffffff9eaa55a0 | W:/Build/J03950001/sys/freebsd/sys/kern/kern_exec.c; copyinstr; native; process_exec_end |
| ffffffff9f006a20 | 0x1F | 0xffffffff9f006a20 | 14B | pure passthrough | 3 fn(s) from 0xffffffff9eaa55a0 | dcons.addr; dcons.size; hw.memtest.tests; hw.physmem |
| ffffffff9f006a30 | 0x5 | 0xffffffff9f006a30 | 14B | pure passthrough | 1 fn(s) from 0xffffffff9eaa55a0 |  |
| ffffffff9f006a40 | 0xA | 0xffffffff9f006a40 | 49B | mov ebx, 0xfffe7960; mov edi, 0xa | 4 fn(s) from 0xffffffff9e8e8b80 | amd_iommu_map; amd_iommu_register_iofault_handler; iommu; iommu_intr |
| ffffffff9f006a80 | 0xB | 0xffffffff9f006a80 | 127B | lea rsi, [rip + 0x76ba47]; lea rcx, [rip + 0x6da27d]; lea r8, [rip + 0x78099d];  | 2 fn(s) from 0xffffffff9e8e9030 | amd_iommu_map; amd_iommu_register_iofault_handler; iommu; iommu_intr |
| ffffffff9f006b00 | 0x6 | 0xffffffff9f006b00 | 31B | mov r9, rcx; mov rcx, rsi | 1 fn(s) from 0xffffffff9e8ea4f0 | amd_iommu_map; amd_iommu_register_iofault_handler; iommu; iommu_intr |
| ffffffff9f006b20 | 0x7 | 0xffffffff9f006b20 | 18B | mov ebx, edi | 2 fn(s) from 0xffffffff9e8ea4f0 | amd_iommu_map; amd_iommu_register_iofault_handler; iommu; iommu_intr |
| ffffffff9f006b40 | 0x8 | 0xffffffff9f006b40 | 20B | mov ecx, esi; mov ebx, edi | 2 fn(s) from 0xffffffff9e8e8b80 | amd_iommu_map; amd_iommu_register_iofault_handler; iommu; iommu_intr |
| ffffffff9f006b60 | 0x9 | 0xffffffff9f006b60 | 20B | mov ecx, esi; mov ebx, edi | 1 fn(s) from 0xffffffff9e8e8d20 |  |
| ffffffff9f006b80 | 0xC | 0xffffffff9f006b80 | 29B | mov r8, rcx; mov ecx, esi; mov ebx, edi | none |  |
| ffffffff9f006ba0 | 0xD | 0xffffffff9f006ba0 | 203B | lea rdx, [rip + 0x76b930]; mov rdi, r14; mov ecx, 0x1ad; xor esi, esi; mov rdi,  | 2 fn(s) from 0xffffffff9f0873d2 | SceTmr; system_resume_phase2; system_suspend_phase2_post_sync; tmr_check_on_boot |
| ffffffff9f006c92 | 0xD | 0xffffffff9f006c92 | 578B | mov rdi, r12; mov ecx, 0x1ec; xor esi, esi; mov rdx, rbx; mov rdi, r12; mov rdi, | none |  |
| ffffffff9f006ee0 | 0xF | 0xffffffff9f006ee0 | 24B | mov rcx, rsi; mov edx, edi | 2 fn(s) from 0xffffffff9e781780 |  |
| ffffffff9f006f00 | 0x10 | 0xffffffff9f006f00 | 14B | pure passthrough | 2 fn(s) from 0xffffffff9e7813b0 |  |
| ffffffff9f006f10 | 0x14 | 0xffffffff9f006f10 | 21B | mov rcx, rsi; mov ebx, edi | 4 fn(s) from 0xffffffff9e6ab2b0 | psp_mbox_map_tmr; sceSblSvpMapPrdyTeeArea; tmrMap |
| ffffffff9f006f30 | 0x15 | 0xffffffff9f006f30 | 18B | mov ebx, edi | 6 fn(s) from 0xffffffff9e6ab2b0 | psp_mbox_map_tmr; sceSblAacs2BlockScanInAccess; sceSblSvpMapPrdyTeeArea; sceSblSvpUnmapPrdyTeeA |
| ffffffff9f006f50 | 0x20 | 0xffffffff9f006f50 | 14B | pure passthrough | 1 fn(s) from 0xffffffff9e651090 |  |
| ffffffff9f006f60 | 0x13 | 0xffffffff9f006f60 | 18B | mov ebx, edi | 1 fn(s) from 0xffffffff9e966270 | KVMKVMKVM; LAPIC; W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; apic |
| ffffffff9f006f80 | 0x1B | 0xffffffff9f006f80 | 49B | mov rcx, rsi; mov rdi, r8; mov r9, qword ptr [rbp + 0x10]; mov r8, r14; mov rsi, | none |  |
| ffffffff9f006fc0 | 0x1C | 0xffffffff9f006fc0 | 14B | pure passthrough | none |  |
| ffffffff9f006fd0 | 0x1D | 0xffffffff9f006fd0 | 22B | mov rcx, rsi | none |  |
| ffffffff9f006ff0 | 0x1E | 0xffffffff9f006ff0 | 14B | pure passthrough | none |  |
| ffffffff9f007000 | 0x26 | 0xffffffff9f007000 | 71B | mov edi, edx; mov ebx, ecx; mov rcx, r15; mov rdx, r14 | none |  |
| ffffffff9f007050 | 0x27 | 0xffffffff9f007050 | 28B | mov ebx, eax | none |  |
| ffffffff9f007070 | 0x28 | 0xffffffff9f007070 | 54B | mov edi, edx; mov ebx, eax | none |  |
| ffffffff9f0071b0 | 0x12 | 0xffffffff9f0071b0 | 408B | mov rdi, r12; xor esi, esi; xor edx, edx; xor ecx, ecx; mov rdi, rbx; mov rdx, r | none |  |

### Hypercall roles (derived from caller string evidence)

| EAX | role (evidence) |
|-----|-----------------|
| 0x4 (4) | CPU-mode set (mode 1) |
| 0x1F (31) | CPU-mode set (mode 0) |
| 0x5 (5) | CPU-mode set (mode 2) |
| 0xA (10) | IOMMU op w/ retry (100000 x delay(10)) |
| 0xB (11) | IOMMU 3x-u64 exchange (logged) |
| 0x6 (6) | IOMMU query (returns u64+u32) |
| 0x7 (7) | IOMMU op (arg in EBX) |
| 0x8 (8) | IOMMU op (EBX,ECX) |
| 0x9 (9) | IOMMU op (EBX,ECX) |
| 0xC (12) | returns 2 u64 (unused) |
| 0xD (13) | HV state block read (EBX=idx -> 4x u64) |
| 0xF (15) | 3-arg op (EDI->EDX, ESI->ECX, EDX->RBX) |
| 0x10 (16) | AP start/resume |
| 0x14 (20) | map TMR (PSP/TEE trusted region) |
| 0x15 (21) | unmap/TMR control |
| 0x20 (32) | sysctl-exposed HV stat |
| 0x13 (19) | LAPIC timer op |
| 0x1B (27) | unused? |
| 0x1C (28) | unused? |
| 0x1D (29) | unused? |
| 0x1E (30) | unused? |
| 0x26 (38) | unused? |
| 0x27 (39) | unused? |
| 0x28 (40) | unused? |
| 0x12 (18) | kern_hv.c internal init |

## 2. MSR usage map

- 1397 verified rdmsr/wrmsr sites (fn-anchored alignment), 197 distinct MSR keys.
- ECX tracking covers `mov ecx,imm`, `mov rcx,imm`, `movabs rcx,imm` (Sony uses all three).

| MSR | label | dir | R | W | sites | first site | funcs | subsystem evidence |
|-----|-------|-----|---|---|-------|------------|-------|---------------------|
| 0x00000000 | CUSTOM/UNKNOWN | R+W | 2 | 2 | 4 | 0xffffffff9e9f49dc | 3 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; PowerUsage; avera |
| 0x00000001 | CUSTOM/UNKNOWN | R | 1 | 0 | 1 | 0xffffffff9ed667e5 | 1 |  |
| 0x00000003 | CUSTOM/UNKNOWN | R | 2 | 0 | 2 | 0xffffffff9e9f4f8c | 1 | copyout |
| 0x00000010 | TSC | R | 2 | 0 | 2 | 0xffffffff9f00f36f | 2 | mp4_queue0; mp4_queue1; mp4_queue_mtx0 |
| 0x0000001B | IA32_APIC_BASE | R+W | 2 | 2 | 4 | 0xffffffff9e96655f | 1 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x0000003A | CUSTOM/UNKNOWN | R | 1 | 0 | 1 | 0xffffffff9ed5a67a | 1 | AuthenticAMD; EM64T; Unknown |
| 0x000000E7 | IA32_MPERF | R+W | 4 | 4 | 8 | 0xffffffff9ebb0865 | 4 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/cpu_machdep.c; AuthenticAMD |
| 0x000000E8 | IA32_APERF | R+W | 4 | 4 | 8 | 0xffffffff9ebb0870 | 4 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/cpu_machdep.c; AuthenticAMD |
| 0x000000FE | CUSTOM/UNKNOWN | R | 1 | 0 | 1 | 0xffffffff9e9df630 | 1 |  |
| 0x00000179 | CUSTOM/UNKNOWN | R | 3 | 0 | 3 | 0xffffffff9ed66343 | 2 | count; force_scan; interval |
| 0x0000017A | CUSTOM/UNKNOWN | R+W | 2 | 1 | 3 | 0xffffffff9ed66796 | 2 |  |
| 0x0000017B | CUSTOM/UNKNOWN | W | 0 | 1 | 1 | 0xffffffff9ed6635b | 1 | count; force_scan; interval |
| 0x00000198 | IA32_PERF_STATUS | R | 8 | 0 | 8 | 0xffffffff9efee9d8 | 2 | AuthenticAMD; acpi_perf; est |
| 0x00000199 | IA32_PERF_CONTROL | R+W | 3 | 3 | 6 | 0xffffffff9efeed9d | 1 | AuthenticAMD; acpi_perf; est |
| 0x0000019A | IA32_CLOCK_MODULATION | R+W | 4 | 3 | 7 | 0xffffffff9e738f85 | 1 | p4tcc; pslinkHidApp_headset_GetData; pslinkHidApp_headset_GetEqBandVal |
| 0x000001A0 | IA32_MISC_ENABLE | R+W | 3 | 1 | 4 | 0xffffffff9ed5b165 | 2 | AuthenticAMD; acpi_perf; est |
| 0x000001D9 | IA32_DEBUGCTL | W | 0 | 5 | 5 | 0xffffffff9e7811ad | 5 | break; dcons.addr; dcons.size |
| 0x000001DB | LastBranch_FromIP0 | R | 1 | 0 | 1 | 0xffffffff9e7de26c | 1 | break |
| 0x000001DC | LastBranch_ToIP0 | R | 1 | 0 | 1 | 0xffffffff9e7de283 | 1 | break |
| 0x000001DD | LastBranch_Info? (non-std) | R | 64 | 0 | 64 | 0xffffffff9e642afd | 18 | SMAP; UNKNOWN; data |
| 0x000001DE | LastBranch_TOS? | R | 64 | 0 | 64 | 0xffffffff9e642b15 | 18 | SMAP; UNKNOWN; data |
| 0x00000250 | MTRRfix64K_00000 | R+W | 2 | 1 | 3 | 0xffffffff9e9dfd1c | 2 | BIOS |
| 0x00000258 | MTRRfix16K_80000 | R+W | 2 | 1 | 3 | 0xffffffff9e9dfda8 | 2 | BIOS |
| 0x00000259 | MTRRfix16K_C0000 | R | 1 | 0 | 1 | 0xffffffff9e9dfe38 | 1 | BIOS |
| 0x00000268 | MTRRfix4K_C0000 | R+W | 1 | 1 | 2 | 0xffffffff9e9e0995 | 1 |  |
| 0x00000277 | IA32_PAT | W | 0 | 1 | 1 | 0xffffffff9eccd249 | 1 |  |
| 0x000002FE | CUSTOM/UNKNOWN | W | 0 | 1 | 1 | 0xffffffff9e9f48dd | 1 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c |
| 0x000002FF | MTRRdefType | R+W | 3 | 3 | 6 | 0xffffffff9e9df647 | 3 |  |
| 0x0000030E | CUSTOM/UNKNOWN | W | 0 | 1 | 1 | 0xffffffff9e9f4959 | 1 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c |
| 0x000003F5 | CUSTOM/UNKNOWN | W | 0 | 1 | 1 | 0xffffffff9e9f431b | 1 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c |
| 0x00000400 | MC0_CTL | W | 0 | 1 | 1 | 0xffffffff9ed66611 | 1 | count; force_scan; interval |
| 0x00000401 | MC0_STATUS | W | 0 | 1 | 1 | 0xffffffff9ed6661c | 1 | count; force_scan; interval |
| 0x00000404 | MC1_CTL | W | 0 | 1 | 1 | 0xffffffff9ed6662d | 1 | count; force_scan; interval |
| 0x00000405 | MC1_STATUS | W | 0 | 1 | 1 | 0xffffffff9ed66643 | 1 | count; force_scan; interval |
| 0x00000408 | MC2_CTL | W | 0 | 1 | 1 | 0xffffffff9ed66654 | 1 | count; force_scan; interval |
| 0x00000409 | MC2_STATUS | W | 0 | 1 | 1 | 0xffffffff9ed6665f | 1 | count; force_scan; interval |
| 0x0000040C | MC3_CTL | W | 0 | 2 | 2 | 0xffffffff9e9f47f3 | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; count; force_scan |
| 0x0000040D | MC3_STATUS | W | 0 | 1 | 1 | 0xffffffff9ed6667b | 1 | count; force_scan; interval |
| 0x00000410 | MC4_CTL | W | 0 | 1 | 1 | 0xffffffff9ed666b7 | 1 | count; force_scan; interval |
| 0x00000411 | MC4_STATUS | W | 0 | 1 | 1 | 0xffffffff9ed666c2 | 1 | count; force_scan; interval |
| 0x00000414 | MC5_CTL | W | 0 | 1 | 1 | 0xffffffff9ed666d3 | 1 | count; force_scan; interval |
| 0x00000415 | MC5_STATUS | W | 0 | 1 | 1 | 0xffffffff9ed666de | 1 | count; force_scan; interval |
| 0x00000418 | MC6_CTL | W | 0 | 1 | 1 | 0xffffffff9ed666ef | 1 | count; force_scan; interval |
| 0x00000419 | MC6_STATUS | W | 0 | 1 | 1 | 0xffffffff9ed666fa | 1 | count; force_scan; interval |
| 0x00000480 | MTRRphysBase0 | R | 1 | 0 | 1 | 0xffffffff9ed5a693 | 1 | AuthenticAMD; EM64T; Unknown |
| 0x00000481 | MTRRphysMask0 | R | 1 | 0 | 1 | 0xffffffff9ed5a6a9 | 1 | AuthenticAMD; EM64T; Unknown |
| 0x00000482 | MTRRphysBase1 | R | 1 | 0 | 1 | 0xffffffff9ed5a6b3 | 1 | AuthenticAMD; EM64T; Unknown |
| 0x00000483 | MTRRphysMask1 | R | 1 | 0 | 1 | 0xffffffff9ed5a6d0 | 1 | AuthenticAMD; EM64T; Unknown |
| 0x00000484 | CUSTOM/UNKNOWN | R | 1 | 0 | 1 | 0xffffffff9ed5a6d9 | 1 | AuthenticAMD; EM64T; Unknown |
| 0x0000048B | MTRRphysBase? | R | 2 | 0 | 2 | 0xffffffff9ed5a6c7 | 1 | AuthenticAMD; EM64T; Unknown |
| 0x0000048C | MTRRphysMask? | R | 1 | 0 | 1 | 0xffffffff9ed5a8ab | 1 | AuthenticAMD; EM64T; Unknown |
| 0x0000048D | MTRRphysBase? | R | 1 | 0 | 1 | 0xffffffff9ed5a77a | 1 | AuthenticAMD; EM64T; Unknown |
| 0x0000048E | MTRRphysMask? | R | 1 | 0 | 1 | 0xffffffff9ed5a784 | 1 | AuthenticAMD; EM64T; Unknown |
| 0x0000048F | MTRRphysBase? | R | 1 | 0 | 1 | 0xffffffff9ed5a7a1 | 1 | AuthenticAMD; EM64T; Unknown |
| 0x00000490 | MTRRphysMask? | R | 1 | 0 | 1 | 0xffffffff9ed5a7aa | 1 | AuthenticAMD; EM64T; Unknown |
| 0x0000052C | CUSTOM/UNKNOWN | R | 1 | 0 | 1 | 0xffffffff9e9f5043 | 1 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0x00000539 | CUSTOM/UNKNOWN | R | 3 | 0 | 3 | 0xffffffff9e9f506e | 1 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0x000006E0 | CUSTOM/UNKNOWN | W | 0 | 3 | 3 | 0xffffffff9e96826a | 2 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x00000800 | CUSTOM/UNKNOWN | R | 1 | 0 | 1 | 0xffffffff9ebe1528 | 1 | TESTING; mDBG:test |
| 0x00000802 | CUSTOM/UNKNOWN | R | 2 | 0 | 2 | 0xffffffff9e96861e | 1 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x00000803 | CUSTOM/UNKNOWN | R | 4 | 0 | 4 | 0xffffffff9e96688c | 1 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x00000808 | CUSTOM/UNKNOWN | R+W | 2 | 1 | 3 | 0xffffffff9e966ab4 | 1 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x0000080B | CUSTOM/UNKNOWN | W | 0 | 2 | 2 | 0xffffffff9e645034 | 2 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x0000080D | CUSTOM/UNKNOWN | R | 1 | 0 | 1 | 0xffffffff9e968648 | 1 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x0000080F | CUSTOM/UNKNOWN | R+W | 4 | 3 | 7 | 0xffffffff9e96659c | 1 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x00000811 | AMD_??_0811 (MCA mask?) | R | 1 | 0 | 1 | 0xffffffff9e6451e9 | 1 |  |
| 0x00000812 | AMD_??_0812 | R | 1 | 0 | 1 | 0xffffffff9e6453b9 | 1 |  |
| 0x00000813 | AMD_??_0813 | R | 1 | 0 | 1 | 0xffffffff9e645589 | 1 |  |
| 0x00000814 | AMD_??_0814 | R | 1 | 0 | 1 | 0xffffffff9e645759 | 1 |  |
| 0x00000815 | AMD_??_0815 | R | 1 | 0 | 1 | 0xffffffff9e645929 | 1 |  |
| 0x00000816 | AMD_??_0816 | R | 1 | 0 | 1 | 0xffffffff9e645af9 | 1 |  |
| 0x00000817 | AMD_??_0817 | R | 1 | 0 | 1 | 0xffffffff9e645cc9 | 1 |  |
| 0x00000828 | CUSTOM/UNKNOWN | R+W | 1 | 2 | 3 | 0xffffffff9e9683ab | 2 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x0000082F | CUSTOM/UNKNOWN | R+W | 2 | 1 | 3 | 0xffffffff9e9683f0 | 1 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x00000830 | CUSTOM/UNKNOWN | R+W | 3 | 2 | 5 | 0xffffffff9e96695d | 1 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x00000832 | CUSTOM/UNKNOWN | R+W | 2 | 9 | 11 | 0xffffffff9e968071 | 3 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x00000833 | CUSTOM/UNKNOWN | R | 1 | 0 | 1 | 0xffffffff9e96876e | 1 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x00000834 | CUSTOM/UNKNOWN | R+W | 1 | 1 | 2 | 0xffffffff9e96805d | 1 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x00000835 | CUSTOM/UNKNOWN | R+W | 2 | 1 | 3 | 0xffffffff9e967f8a | 1 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x00000836 | CUSTOM/UNKNOWN | R+W | 2 | 1 | 3 | 0xffffffff9e967fce | 1 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x00000837 | CUSTOM/UNKNOWN | R+W | 2 | 1 | 3 | 0xffffffff9e96834b | 1 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x00000838 | AMD_MCi_ADDR? | W | 0 | 5 | 5 | 0xffffffff9e9682d4 | 3 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x00000839 | CUSTOM/UNKNOWN | R | 1 | 0 | 1 | 0xffffffff9e96af6f | 1 |  |
| 0x0000083E | CUSTOM/UNKNOWN | W | 0 | 5 | 5 | 0xffffffff9e9681c4 | 3 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x00000841 | AMD_MCi_STATUS? | W | 0 | 1 | 1 | 0xffffffff9e966bb2 | 1 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x00000848 | CUSTOM/UNKNOWN | R+W | 2 | 2 | 4 | 0xffffffff9e96a0ec | 2 |  |
| 0x00000849 | CUSTOM/UNKNOWN | R+W | 2 | 2 | 4 | 0xffffffff9e96a127 | 2 |  |
| 0x0000084A | CUSTOM/UNKNOWN | R+W | 2 | 2 | 4 | 0xffffffff9e96a162 | 2 |  |
| 0x0000084B | CUSTOM/UNKNOWN | R+W | 2 | 2 | 4 | 0xffffffff9e96a1b2 | 2 |  |
| 0x0000084C | CUSTOM/UNKNOWN | R+W | 2 | 2 | 4 | 0xffffffff9e96a214 | 2 |  |
| 0x0000084D | CUSTOM/UNKNOWN | R+W | 34 | 34 | 68 | 0xffffffff9e966bc2 | 3 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x0000084E | CUSTOM/UNKNOWN | R+W | 34 | 34 | 68 | 0xffffffff9e9675c1 | 3 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x0000084F | CUSTOM/UNKNOWN | R+W | 2 | 2 | 4 | 0xffffffff9e96a33a | 2 |  |
| 0x00000850 | CUSTOM/UNKNOWN | R+W | 1 | 1 | 2 | 0xffffffff9e968433 | 1 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x00000851 | CUSTOM/UNKNOWN | R+W | 1 | 1 | 2 | 0xffffffff9e9684e5 | 1 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x00000852 | CUSTOM/UNKNOWN | R+W | 1 | 1 | 2 | 0xffffffff9e96848c | 1 | W:/Build/J03950001/sys/freebsd/sys/x86/x86/local_apic.c; KVMKVMKVM; LA |
| 0x00001107 | CUSTOM/UNKNOWN | R+W | 1 | 1 | 2 | 0xffffffff9ec3ac17 | 1 |  |
| 0x0000110B | CUSTOM/UNKNOWN | R+W | 1 | 1 | 2 | 0xffffffff9ec3abc2 | 1 |  |
| 0x00001203 | CUSTOM/UNKNOWN | R | 1 | 0 | 1 | 0xffffffff9effd7d6 | 1 | cpufreq; cpufreq_levels_changed; cpufreq_post_change |
| 0xC0000080 | EFER | R+W | 4 | 4 | 8 | 0xffffffff9e642874 | 5 | bootflags; icu; kernelname |
| 0xC0000081 | STAR | R+W | 1 | 3 | 4 | 0xffffffff9e642887 | 4 | bootflags; icu; kernelname |
| 0xC0000082 | LSTAR | R+W | 1 | 3 | 4 | 0xffffffff9e64289a | 4 | bootflags; icu; kernelname |
| 0xC0000083 | CSTAR | R+W | 1 | 3 | 4 | 0xffffffff9e6428ad | 4 | bootflags; icu; kernelname |
| 0xC0000084 | FMASK/SFMASK | R+W | 1 | 3 | 4 | 0xffffffff9e6428c0 | 4 | bootflags; icu; kernelname |
| 0xC0000100 | FS_BASE | R+W | 3 | 6 | 9 | 0xffffffff9e64284d | 6 | bootflags; icu; init_secondary_tail |
| 0xC0000101 | GS_BASE | R+W | 5 | 8 | 13 | 0xffffffff9e64285a | 5 | bootflags; icu; kernelname |
| 0xC0000102 | KERNEL_GS_BASE | R+W | 1 | 4 | 5 | 0xffffffff9e642867 | 5 | bootflags; icu; kernelname |
| 0xC0000103 | TSC_AUX | W | 0 | 5 | 5 | 0xffffffff9eaa55ea | 3 | W:/Build/J03950001/sys/freebsd/sys/kern/kern_exec.c; copyinstr; native |
| 0xC000010F | AMD_??_0x10F | W | 0 | 2 | 2 | 0xffffffff9e7de2a1 | 2 | break |
| 0xC0000110 | CUSTOM/UNKNOWN | R+W | 48 | 3 | 51 | 0xffffffff9e642b30 | 2 |  |
| 0xC0000111 | CUSTOM/UNKNOWN | R+W | 48 | 3 | 51 | 0xffffffff9e642b4b | 2 |  |
| 0xC0000112 | CUSTOM/UNKNOWN | R+W | 48 | 3 | 51 | 0xffffffff9e642b66 | 2 |  |
| 0xC0000113 | CUSTOM/UNKNOWN | R+W | 48 | 3 | 51 | 0xffffffff9e642b81 | 2 |  |
| 0xC0000114 | CUSTOM/UNKNOWN | R+W | 48 | 3 | 51 | 0xffffffff9e642b9c | 2 |  |
| 0xC0000115 | CUSTOM/UNKNOWN | R+W | 48 | 3 | 51 | 0xffffffff9e642bb7 | 2 |  |
| 0xC0000116 | CUSTOM/UNKNOWN | R+W | 48 | 3 | 51 | 0xffffffff9e642bd2 | 2 |  |
| 0xC0000117 | CUSTOM/UNKNOWN | R+W | 48 | 3 | 51 | 0xffffffff9e642bed | 2 |  |
| 0xC001001F | AMD_??_001F | R+W | 1 | 1 | 2 | 0xffffffff9ec3ab87 | 1 |  |
| 0xC0010041 | AMD_MC0_CTL_MASK? | R+W | 1 | 8 | 9 | 0xffffffff9ecf4869 | 2 | FAT; GEOM_LABEL; acpi_perf |
| 0xC0010042 | AMD_MC1_CTL_MASK? | R | 10 | 0 | 10 | 0xffffffff9ecf407c | 3 | FAT; GEOM_LABEL; acpi_perf |
| 0xC0010044 | AMD_MC4_CTL_MASK? | R+W | 1 | 1 | 2 | 0xffffffff9ed665af | 1 | count; force_scan; interval |
| 0xC0010055 | AMD_SMM_MASK? | R+W | 1 | 1 | 2 | 0xffffffff9ebb0a83 | 1 | acpi; hlt; mwait |
| 0xC0010061 | AMD_DBGCTL | R | 4 | 0 | 4 | 0xffffffff9e94bac2 | 2 | W:/Build/J03950001/sys/freebsd/sys/x86/cpufreq/hwpstate.c; acpi_perf;  |
| 0xC0010062 | AMD_DBG_STATUS | W | 0 | 1 | 1 | 0xffffffff9e94c0ba | 1 | W:/Build/J03950001/sys/freebsd/sys/x86/cpufreq/hwpstate.c |
| 0xC0010063 | AMD_LASTBRANCH_FROM? | R | 2 | 0 | 2 | 0xffffffff9e94bf64 | 2 | W:/Build/J03950001/sys/freebsd/sys/x86/cpufreq/hwpstate.c; acpi_perf;  |
| 0xC0010064 | AMD_LBR stack (0x64-0x6B) | R+W | 1 | 1 | 2 | 0xffffffff9edfa0e5 | 1 |  |
| 0xC0010065 | CUSTOM/UNKNOWN | R+W | 1 | 1 | 2 | 0xffffffff9edfa0f4 | 1 |  |
| 0xC0010066 | CUSTOM/UNKNOWN | R+W | 1 | 1 | 2 | 0xffffffff9edfa103 | 1 |  |
| 0xC0010067 | CUSTOM/UNKNOWN | R+W | 1 | 1 | 2 | 0xffffffff9edfa112 | 1 |  |
| 0xC0010068 | CUSTOM/UNKNOWN | R+W | 1 | 1 | 2 | 0xffffffff9edfa121 | 1 |  |
| 0xC0010069 | CUSTOM/UNKNOWN | R+W | 1 | 1 | 2 | 0xffffffff9edfa130 | 1 |  |
| 0xC001006A | CUSTOM/UNKNOWN | R+W | 1 | 1 | 2 | 0xffffffff9edfa13f | 1 |  |
| 0xC001006B | CUSTOM/UNKNOWN | R+W | 1 | 1 | 2 | 0xffffffff9edfa14e | 1 |  |
| 0xC0010114 | AMD_??_0114 (C-state?) | R | 1 | 0 | 1 | 0xffffffff9ed5aa71 | 1 | AuthenticAMD; EM64T; Unknown |
| 0xC0010190 | AMD_??_0190 | R+W | 3 | 4 | 7 | 0xffffffff9e9f4a99 | 3 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0xC0010191 | AMD_??_0191 | R+W | 1 | 2 | 3 | 0xffffffff9e9f4cc4 | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; copyout; opmc_res |
| 0xC0010192 | CUSTOM/UNKNOWN | R+W | 3 | 4 | 7 | 0xffffffff9e9f4aa4 | 3 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0xC0010193 | CUSTOM/UNKNOWN | R+W | 1 | 2 | 3 | 0xffffffff9e9f4ccb | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; copyout; opmc_res |
| 0xC0010194 | CUSTOM/UNKNOWN | R+W | 3 | 4 | 7 | 0xffffffff9e9f4ab1 | 3 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0xC0010195 | CUSTOM/UNKNOWN | R+W | 1 | 2 | 3 | 0xffffffff9e9f4cd2 | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; copyout; opmc_res |
| 0xC0010196 | CUSTOM/UNKNOWN | R+W | 3 | 4 | 7 | 0xffffffff9e9f4abe | 3 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0xC0010197 | CUSTOM/UNKNOWN | R+W | 1 | 3 | 4 | 0xffffffff9e9f4cd9 | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; copyout; opmc_res |
| 0xC0010200 | AMD_PERF_CTL[0] | W | 0 | 4 | 4 | 0xffffffff9e6425de | 3 |  |
| 0xC0010201 | AMD_PERF_CTR[0] | R+W | 4 | 4 | 8 | 0xffffffff9e642614 | 6 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; copyout |
| 0xC0010202 | AMD_PERF_CTL[1] | W | 0 | 4 | 4 | 0xffffffff9e6425e5 | 3 |  |
| 0xC0010203 | AMD_PERF_CTR[1] | R+W | 4 | 4 | 8 | 0xffffffff9e642629 | 6 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; copyout |
| 0xC0010204 | AMD_PERF_CTL[2] | W | 0 | 4 | 4 | 0xffffffff9e6425ec | 3 |  |
| 0xC0010205 | AMD_PERF_CTR[2] | R+W | 4 | 4 | 8 | 0xffffffff9e64263e | 6 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; copyout |
| 0xC0010206 | AMD_PERF_CTL[3] | W | 0 | 4 | 4 | 0xffffffff9e6425f3 | 3 |  |
| 0xC0010207 | AMD_PERF_CTR[3] | R+W | 4 | 4 | 8 | 0xffffffff9e642653 | 6 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; copyout |
| 0xC0010208 | AMD_PERF_CTL[4] | W | 0 | 4 | 4 | 0xffffffff9e6425fa | 3 |  |
| 0xC0010209 | AMD_PERF_CTR[4] | R+W | 4 | 4 | 8 | 0xffffffff9e642668 | 6 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; copyout |
| 0xC001020A | AMD_PERF_CTL[5] | W | 0 | 4 | 4 | 0xffffffff9e642601 | 3 |  |
| 0xC001020B | AMD_PERF_CTR[5] | R+W | 4 | 4 | 8 | 0xffffffff9e64267d | 6 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; copyout |
| 0xC0010230 | AMD_??_0230 (Zen IBS?) | R+W | 6 | 10 | 16 | 0xffffffff9e9f3dee | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0xC0010231 | AMD_??_0231 | R+W | 2 | 4 | 6 | 0xffffffff9e9f474c | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0xC0010232 | AMD_??_0232 | R+W | 6 | 10 | 16 | 0xffffffff9e9f3e04 | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0xC0010233 | AMD_??_0233 | R+W | 2 | 4 | 6 | 0xffffffff9e9f4753 | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0xC0010234 | CUSTOM/UNKNOWN | R+W | 6 | 10 | 16 | 0xffffffff9e9f3e10 | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0xC0010235 | CUSTOM/UNKNOWN | R+W | 2 | 4 | 6 | 0xffffffff9e9f475a | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0xC0010236 | CUSTOM/UNKNOWN | R+W | 6 | 10 | 16 | 0xffffffff9e9f3e1d | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0xC0010237 | CUSTOM/UNKNOWN | R+W | 2 | 4 | 6 | 0xffffffff9e9f4761 | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0xC0010238 | CUSTOM/UNKNOWN | R+W | 6 | 10 | 16 | 0xffffffff9e9f3e2a | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0xC0010239 | CUSTOM/UNKNOWN | R+W | 2 | 4 | 6 | 0xffffffff9e9f4768 | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0xC001023A | CUSTOM/UNKNOWN | R+W | 6 | 10 | 16 | 0xffffffff9e9f3e37 | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0xC001023B | CUSTOM/UNKNOWN | R+W | 2 | 4 | 6 | 0xffffffff9e9f476f | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0xC0010240 | AMD_??_0240 | R+W | 3 | 4 | 7 | 0xffffffff9e9f4a01 | 3 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0xC0010241 | AMD_??_0241 | R+W | 1 | 2 | 3 | 0xffffffff9e9f4c8b | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; copyout; opmc_res |
| 0xC0010242 | CUSTOM/UNKNOWN | R+W | 3 | 4 | 7 | 0xffffffff9e9f4a0c | 3 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0xC0010243 | CUSTOM/UNKNOWN | R+W | 1 | 2 | 3 | 0xffffffff9e9f4c92 | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; copyout; opmc_res |
| 0xC0010244 | CUSTOM/UNKNOWN | R+W | 3 | 4 | 7 | 0xffffffff9e9f4a19 | 3 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0xC0010245 | CUSTOM/UNKNOWN | R+W | 1 | 2 | 3 | 0xffffffff9e9f4c99 | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; copyout; opmc_res |
| 0xC0010246 | CUSTOM/UNKNOWN | R+W | 3 | 4 | 7 | 0xffffffff9e9f4a26 | 3 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; opmc_resume; opmc |
| 0xC0010247 | CUSTOM/UNKNOWN | R+W | 1 | 2 | 3 | 0xffffffff9e9f4ca0 | 2 | W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c; copyout; opmc_res |
| 0xC0011005 | AMD_??_1005 | R+W | 1 | 2 | 3 | 0xffffffff9ed5b1a1 | 1 |  |
| 0xC0011019 | AMD_??_1019 | R+W | 2 | 3 | 5 | 0xffffffff9e6423b4 | 4 | copyin |
| 0xC001101A | AMD_??_101A | R+W | 2 | 3 | 5 | 0xffffffff9e6423c9 | 4 | copyin |
| 0xC001101B | AMD_??_101B | R+W | 2 | 3 | 5 | 0xffffffff9e6423de | 4 | copyin |
| 0xC0011024 | AMD_??_1024 | R+W | 2 | 3 | 5 | 0xffffffff9e64241d | 4 | copyin |
| 0xC0011025 | AMD_??_1025 | R+W | 2 | 3 | 5 | 0xffffffff9e6423f3 | 4 | copyin |
| 0xC0011026 | AMD_??_1026 | R+W | 2 | 3 | 5 | 0xffffffff9e642408 | 4 | copyin |
| 0xC0011027 | AMD_??_1027 | R+W | 2 | 3 | 5 | 0xffffffff9e64239f | 4 | copyin |
| 0xC0011029 | AMD_??_1029 | R+W | 1 | 1 | 2 | 0xffffffff9ec3ab49 | 1 |  |
| 0xC0011033 | AMD_??_1033 (Zen2?) | R+W | 4 | 15 | 19 | 0xffffffff9e96966e | 3 |  |
| 0xC0011074 | AMD_??_1074 | R+W | 1 | 2 | 3 | 0xffffffff9eda2250 | 1 | W:/Build/J03950001/sys/internal/modules/mp1/bapm_param_set/bapm_param_ |
| 0xC0011076 | AMD_??_1076 | W | 0 | 1 | 1 | 0xffffffff9eda227a | 1 | W:/Build/J03950001/sys/internal/modules/mp1/bapm_param_set/bapm_param_ |
| 0xC0011077 | AMD_??_1077 | W | 0 | 1 | 1 | 0xffffffff9eda2293 | 1 | W:/Build/J03950001/sys/internal/modules/mp1/bapm_param_set/bapm_param_ |
| 0xC0011083 | AMD_??_1083 | R | 1 | 0 | 1 | 0xffffffff9ebe1083 | 1 |  |
| 0xC00110AD | AMD_??_10AD (Zen2 resync?) | R | 6 | 0 | 6 | 0xffffffff9e72f8a1 | 6 | _gbase_free_vm_space; gbase_gvmsw_close; gbase_gvmsw_invalidate_tlb |

Dynamic-ECX sites (MSR index from register):

- ['dynamic'] — dir R+W, 4 site(s), first 0xffffffff9e649aed
- ['none'] — dir R+W, 15 site(s), first 0xffffffff9e71100d
- ['dynamic'] — dir R, 1 site(s), first 0xffffffff9e9dfef8
- ['dynamic'] — dir R, 2 site(s), first 0xffffffff9e9dffea
- ['dynamic'] — dir R+W, 3 site(s), first 0xffffffff9e9e0cc8
- ['dynamic'] — dir R, 1 site(s), first 0xffffffff9ebe1bcf
- ['dynamic'] — dir R+W, 4 site(s), first 0xffffffff9ed668b3
- ['dynamic'] — dir W, 1 site(s), first 0xffffffff9e9e0ca8

## 3. Kernel entry & boot order

### Entry chain

1. Image starts 0xffffffff9e3f0000: 16B data blob, then boot stub at 0x9e3f0010.
2. Boot stub: temp `lgdt` (GDT @ 0xffffffffa1e8dce0, limit 0x40), DS/SS=0x28,
   `retfq` to CS=0x20 -> reload real GDTR -> `call 0xffffffff9e6428f0` (hammer_time).
3. hammer_time (0x9e6428f0, ~10KB fn): load CR3, segments (FS=0x13/GS=0x1b),
   restore FS_BASE/GS_BASE/KGS_BASE/EFER/STAR/LSTAR/CSTAR/SFMASK + CR0/2/3/4 +
   IDT/LDT/TR from context struct at RDI (pair: save-fn 0x9e6427d0 uses same offsets).
4. 0xCC padding zone: [0x9e3f0090, 0x9e64025f) = 2,425,295 B (2.43 MB), 1 island of 8 zero bytes.
5. Real code starts 0xffffffff9e64025f; first fn contains `lgdt` @0x9e640433.

### sysinit_set (Sony layout, live-dump state)

- Array: [0xffffffff9fe51fb0, 0xffffffff9fe55068) — 1559 entries.
- Struct: {u32 done_stamp, u32 order, thunk-func*, udata*}; thunk region
  0x9e651000..0x9e656000 = 16B `jmp real` islands (KASLR-style indirection).
- **Array order == execution order** (linker pre-sorted; live dump shows done=1 stamped).

### Subsystem bring-up order (from kernel's own file-path strings)

| boot # | subsystem (file) |
|--------|------------------|
| #44 | kern/init_main.c |
| #518 | kern/kern_synch.c |
| #522 | kern/kern_descrip.c |
| #592 | fs/mlfs/mlfs_vfsops.c |
| #684 | kern/orbis_cpumode.c |
| #705 | kern/kern_idle.c |
| #706 | kern/sce_cpurv.c |
| #713 | kern/kern_intr.c |
| #1039 | x86/x86/mca.c |
| #1087 | kern/vfs_subr.c |
| #1091 | kern/vfs_lookup.c |
| #1114 | kern/kern_clock.c |
| #1184 | kern/subr_autoconf.c |
| #1188 | kern/orbis_pmc.c |
| #1197 | vm/vm_pageout.c |
| #1222 | kern/sce_svmd.c |
| #1235 | W:/Build/J03950001/sys/mp4/x86/kernel/modules/a53mm/a53mm_event.c:180 |

Total: 1559 boot entries; full per-entry table in wp1_3_sysinit.json.

Adjacent set [0x9fe55070, 0x9fe57508) = 1171 teardown/uninit entries using the
STANDARD FreeBSD 9.3 SI_SUB enum (KMEM x460 = vmem arenas, LOCK x132, ...) — shutdown path.