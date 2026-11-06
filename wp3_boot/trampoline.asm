; ============================================================================
; PS5 13.60 kernel boot trampoline (WP3-STEP 3)
; QEMU multiboot ELF32, linked at 0x100000, loaded by -kernel.
; The kernel image (kernel_raw.bin, 62.2MiB) is passed as a multiboot module
; via -initrd and copied to phys 0x1E3F0000.
;
; Implements the 20-item Loader Contract:
;   * kernel image copy to [0x1E3F0000, 0x22224000)
;   * 41 in-memory boot patches (hypercall shim 0x1F->0, console un-mute,
;     pmap_bootstrap forced constants, Titania putc -> debugcon 0x402)
;   * phys param block at 0x9B000..0x9C000 + contract words (0x9bf4c/54/6f4)
;   * preload metadata page at 0x22224000 (modulep), SMAP with 1GB physmem top
;   * initial page tables: identity slot0 + KVA window slot0x1FF + DMAP window
;     (slot 0x11C, PDPT 0x1DC — matches the live kernel constants we force)
;   * btext entry: rsp -> [any][modulep>>12][physfree>>12], jump 0xffffffff9e642a90
; ============================================================================

KERN_PHYS   equ 0x1E3F0000
KERN_SIZE   equ 0x3E34000
MODULEP     equ 0x22224000
PHYSFREE    equ 0x22225000

PML4        equ 0x80000
PDPT_ID     equ 0x81000
PDPT_KVA    equ 0x82000
PDPT_DMAP   equ 0x83000
PD_ID       equ 0x84000
PD_KVA      equ 0x85000
PD_DMAP     equ 0x86000
PT_END      equ 0x87000

TRAMP_STACK equ 0x88000           ; trampoline stack (transient)
BTEXT_STACK equ 0x97000           ; btext entry rsp (transient; kernel switches to own bootstack)

DMAP_PML4I  equ 0x11C             ; from live constants d39=0x11c, d30=0x1dc
DMAP_PDPTI  equ 0x1DC
KVA_PML4I   equ 0x1FF

MB_MAGIC    equ 0x2BADB002

%include "patches.inc"
%include "meta.inc"
%include "params.inc"

section .multiboot
align 4
    dd 0x1BADB002
    dd 0x00000003                  ; want mem info; ELF kernel (no kludge bit)
    dd -(0x1BADB002 + 0x00000003)

section .bss
align 16
tramp_stack_bottom:
    resb 16384
tramp_stack_top:
mbi_ptr:   resd 1
mod_start: resd 1
mod_len:   resd 1
pcount:    resd 1
plen:      resd 1
ebda_base: resd 1
rsdp_count: resd 1

section .rodata
s_boot:  db "PS5-TRAMPOLINE: booting 13.60 kernel", 10, 0
s_nomod: db "PS5-TRAMPOLINE: ERROR no module!", 10, 0
s_len:   db "PS5-TRAMPOLINE: ERROR bad module size!", 10, 0
s_pat:   db "PS5-TRAMPOLINE: patch mismatch at ", 0
s_nl:    db 10, 0
s_done:  db "PS5-TRAMPOLINE: entering long mode -> btext 0xffffffff9e642a90", 10, 0
s_ptdbg: db "PT-VERIFY:", 0
s_pt1:   db " PML4[1FF]=", 0
s_pt2:   db " PDPT_KVA[0]=", 0
s_pt3:   db " PD_KVA[F3]=", 0
s_pt4:   db "/", 0

section .text
global _start

; --- tiny helpers (32-bit) ---
putc:
    ; al = char
    mov dx, 0x402
    out dx, al
    ret
puts:
    ; esi = NUL-terminated
    push esi
    push eax
.l: lodsb
    test al, al
    jz .d
    call putc
    jmp .l
.d: pop eax
    pop esi
    ret
puthex32:
    ; eax = value
    push eax
    push ebx
    push ecx
    mov ebx, eax
    mov ecx, 8
.l: rol ebx, 4
    mov al, bl
    and al, 0x0F
    cmp al, 10
    jb .dig
    add al, 'A'-10
    jmp .o
.dig:
    add al, '0'
.o: call putc
    loop .l
    pop ecx
    pop ebx
    pop eax
    ret

_start:
    cli
    cld
    mov esp, tramp_stack_top
    mov [mbi_ptr], ebx

    ; flat 32-bit segments via our GDT (QEMU multiboot sets usable ones, but be safe)
    lgdt [gdtdesc]
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    mov eax, 0x08
    push eax
    push dword .flush
    retf
.flush:

    mov esi, s_boot
    call puts

    ; ---------------- locate the kernel module ----------------
    test dword [ebx], 8            ; mbi flags bit3: mods valid
    jz no_mod
    mov ecx, [ebx + 20]            ; mods_count
    test ecx, ecx
    jz no_mod
    mov edx, [ebx + 24]            ; mods_addr
    mov esi, [edx]                 ; mod_start
    mov edi, [edx + 4]             ; mod_end
    sub edi, esi                   ; length
    mov [mod_start], esi
    mov [mod_len], edi
    cmp edi, KERN_SIZE
    jne bad_len

    ; ---------------- copy kernel image to 0x1E3F0000 ----------------
    ; overlap-safe direction select
    mov eax, esi
    add eax, edi                   ; src_end
    cmp eax, KERN_PHYS             ; src_end <= dst_start -> forward
    jbe .fwd
    mov eax, KERN_PHYS
    add eax, edi                   ; dst_end
    cmp eax, esi                   ; dst_end <= src_start -> forward
    jbe .fwd
    ; backward copy
    mov ecx, edi
    shr ecx, 2
    mov eax, [mod_start]
    add eax, edi
    mov esi, eax
    sub esi, 4                     ; esi = src_end-4
    lea edi, [KERN_PHYS + KERN_SIZE - 4]
    std
    rep movsd
    cld
    jmp .copied
.fwd:
    mov esi, [mod_start]
    mov edi, KERN_PHYS
    mov ecx, [mod_len]
    shr ecx, 2
    rep movsd
.copied:

    ; ---------------- apply boot patches ----------------
    mov dword [pcount], PATCH_COUNT
    mov esi, patch_table
.ploop:
    lodsd                          ; img offset
    mov edx, eax
    add edx, KERN_PHYS             ; target phys
    lodsd                          ; len
    mov [plen], eax
    mov ecx, eax
    mov edi, edx                   ; verify target
    push esi
    push ecx
.vloop:
    lodsb                          ; expected byte
    cmp al, [edi]
    jne .pmismatch
    inc edi
    loop .vloop
    pop ecx
    pop esi
    add esi, [plen]                ; skip expect[] -> esi at new[]
    mov edi, edx
    mov ecx, [plen]
.wloop:
    lodsb
    mov [edi], al
    inc edi
    loop .wloop
    dec dword [pcount]
    jnz .ploop
    jmp .patches_done
.pmismatch:
    ; print mismatch address
    mov esi, s_pat
    call puts
    mov eax, edx
    call puthex32
    mov esi, s_nl
    call puts
    cli
    hlt
.patches_done:

    ; ---------------- write phys params (incl. contract words) ----------------
    ; zero [0x9B000, 0x9C000)
    mov edi, 0x9B000
    mov ecx, 0x1000 / 4
    xor eax, eax
    rep stosd
    mov esi, param_table
    mov ecx, PARAM_COUNT
.par_loop:
    push ecx
    lodsd                          ; phys
    mov edi, eax
    lodsd                          ; len
    mov ecx, eax
.pbloop:
    lodsb
    mov [edi], al
    inc edi
    loop .pbloop
    pop ecx
    loop .par_loop
    ; cold-boot warm flag
    mov dword [0x472], 0

    ; ---------------- hide ACPI RSDP from the kernel ----------------
    ; The PS5 kernel must not execute QEMU/SeaBIOS PC AML. Corrupt the
    ; 'RSD PTR ' signature in the EBDA and the 0xE0000-0x100000 scan range.
    ; EBDA base = word at 0x40E (in 1KB units)
    xor eax, eax
    mov ax, [0x40E]
    shl eax, 10                   ; EBDA phys
    mov [ebda_base], eax
    ; scan EBDA (up to 1KB) and [0xE0000, 0x100000) for 'RSD PTR '
    mov dword [rsdp_count], 0
    mov eax, [ebda_base]
    mov ecx, 0x400
    call rsdp_scan
    mov eax, 0xE0000
    mov ecx, 0x20000
    call rsdp_scan

    ; ---------------- preload metadata page @ 0x22224000 ----------------
    mov edi, MODULEP
    mov ecx, 0x1000 / 4
    xor eax, eax
    rep stosd
    mov esi, meta_blob
    mov edi, MODULEP
    mov ecx, META_LEN
.mloop:
    lodsb
    mov [edi], al
    inc edi
    loop .mloop

    ; ---------------- build initial page tables ----------------
    ; zero PT pages [0x80000, 0x87000)
    mov edi, PML4
    mov ecx, (PT_END - PML4) / 4
    xor eax, eax
    rep stosd
    ; PML4 wiring
    mov dword [PML4 + 0],            PDPT_ID | 3
    mov dword [PML4 + KVA_PML4I*8],  PDPT_KVA | 3
    mov dword [PML4 + DMAP_PML4I*8], PDPT_DMAP | 3
    ; PDPT wiring
    mov dword [PDPT_ID + 0],              PD_ID | 3
    ; KVA window 0xFFFFFFFF80000000 lives at PML4[0x1FF].PDPT[0x1FE] (NOT 0!)
    mov dword [PDPT_KVA + 0x1FE*8],       PD_KVA | 3
    mov dword [PDPT_DMAP + DMAP_PDPTI*8], PD_DMAP | 3
    ; PD fill: 512 entries of 2MB pages, phys = i*2MB | 0x83 (PS|RW|P)
    mov edi, PD_ID
    mov eax, 0x83
    mov ecx, 512
.pdid:  mov [edi], eax
    add eax, 0x200000
    add edi, 8
    loop .pdid
    mov edi, PD_KVA
    mov eax, 0x83
    mov ecx, 512
.pdkva: mov [edi], eax
    add eax, 0x200000
    add edi, 8
    loop .pdkva
    mov edi, PD_DMAP
    mov eax, 0x83
    mov ecx, 512
.pddm:  mov [edi], eax
    add eax, 0x200000
    add edi, 8
    loop .pddm

    mov esi, s_done
    call puts

    ; ---------------- PT verification (debug) ----------------
    mov esi, s_ptdbg
    call puts
    mov esi, s_pt1
    call puts
    mov eax, [0x80FF8]        ; PML4[0x1FF]
    call puthex32
    mov esi, s_pt2
    call puts
    mov eax, [0x82000]        ; PDPT_KVA[0]
    call puthex32
    mov esi, s_pt3
    call puts
    mov eax, [0x85000 + 0xF3*8]  ; PD_KVA[0xF3]
    call puthex32
    mov esi, s_pt4
    call puts
    mov eax, [0x85000 + 0xF3*8 + 4]
    call puthex32
    mov esi, s_nl
    call puts

    ; ---------------- enter long mode ----------------
    mov eax, cr4
    or eax, 0x20                   ; PAE
    mov cr4, eax
    mov eax, PML4
    mov cr3, eax
    mov ecx, 0xC0000080            ; EFER
    rdmsr
    or eax, 0x100                  ; LME
    wrmsr
    mov eax, cr0
    or eax, 0x80000000             ; PG (PE already set)
    mov cr0, eax
    jmp 0x18:long_mode

; ---- rsdp_scan: eax=base, ecx=len — corrupts 'RSD PTR ' signatures ----
rsdp_scan:
    push eax
    push ecx
    push esi
    mov esi, eax
    test ecx, ecx
    jz .done
.l:
    cmp dword [esi], 0x20445352           ; 'RSD '
    jne .next
    cmp dword [esi + 4], 0x20525450       ; 'PTR '
    jne .next
    ; corrupt: change first byte to 0
    mov byte [esi], 0
    inc dword [rsdp_count]
.next:
    inc esi
    dec ecx
    jnz .l
.done:
    pop esi
    pop ecx
    pop eax
    ret

.pdone:
no_mod:
    mov esi, s_nomod
    call puts
    cli
    hlt
bad_len:
    mov esi, s_len
    call puts
    mov esi, s_len2
    call puts
    mov eax, [mod_len]
    call puthex32
    mov esi, s_nl
    call puts
    cli
    hlt

; ---------------- 64-bit part ----------------
[bits 64]
long_mode:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax

    ; ---------------- loader contract: EARLY GS BASE (fake pcpu) ----------------
    ; The Sony loader sets GS base before kernel entry; machine_init re-sets it at
    ; +0x2D7 (wrmsr 0xC0000101 = real pcpu 0xffffffffa1fb8f00). Everything before
    ; that (cpu-init hook, stats counters) reads gs:[0]/[0x10]/[0x20].
    ; Fake pcpu @ phys 0x99000 (KVA 0xffffffff8099000), 8KB scratch, zeroed:
    mov rdi, 0x99000
    mov ecx, 0x2000 / 8
    xor eax, eax
    rep stosq
    mov rax, 0xffffffff80099a00         ; fake thread (curthread)
    mov [qword 0x99000], rax
    mov rax, 0xffffffff8009aa00         ; fake proc (curproc)
    mov [qword 0x99010], rax
    mov rax, 0xffffffff80099000         ; curpcpu = self
    mov [qword 0x99020], rax
    mov ecx, 0xC0000101                 ; MSR_GS_BASE
    mov eax, 0x80099000
    mov edx, 0xffffffff
    wrmsr
    mov ecx, 0xC0000102                 ; MSR_KERNEL_GS_BASE
    xor eax, eax
    xor edx, edx
    wrmsr

    ; btext entry stack: [rsp+4] = modulep>>12, [rsp+8] = physfree>>12 (dwords)
    mov dword [BTEXT_STACK + 0], 0
    mov dword [BTEXT_STACK + 4], MODULEP >> 12
    mov dword [BTEXT_STACK + 8], PHYSFREE >> 12
    mov rsp, BTEXT_STACK
    mov rax, 0xFFFFFFFF9E642A90    ; btext
    jmp rax

section .rodata
s_len2: db "PS5-TRAMPOLINE: module size = ", 0

; ---------------- GDT ----------------
align 8
gdt:
    dq 0                           ; 0x00 null
    dq 0x00CF9A000000FFFF          ; 0x08 code32
    dq 0x00CF92000000FFFF          ; 0x10 data
    dq 0x00AF9A000000FFFF          ; 0x18 code64 (L=1)
gdtdesc:
    dw gdtdesc - gdt - 1
    dd gdt
