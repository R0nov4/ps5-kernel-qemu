; WP3-STEP 3a: MSR probe kernel (32-bit multiboot) — tests the 10 trap-frame MSRs
; plus key early-boot MSRs and VMMCALL behavior under QEMU TCG.
; Output via QEMU debugcon (port 0x402). Build: nasm -f elf32

MB_MAGIC  equ 0x1BADB002
MB_FLAGS equ 0x00000003          ; need modules info? no — plain
MB_CHECK equ -(MB_MAGIC + MB_FLAGS)

ORG 0x100000
MB_FLAGS2 equ 0x00010003           ; a.out kludge + modules info
section .text
_start_of_file:
    dd 0x1BADB002
    dd MB_FLAGS2
    dd -(0x1BADB002 + MB_FLAGS2)
    dd _start_of_file               ; header_addr
    dd _start_of_file               ; load_addr
    dd _end_of_data                 ; load_end_addr
    dd _end_of_bss                  ; bss_end_addr
    dd _start                       ; entry_addr

section .bss
stack_bottom:
    resb 16384
stack_top:
idt:
    resb 256*8

section .data
align 4
msr_list:
    dd 0x1DD, 0x1DE
    dd 0xC0000110, 0xC0000111, 0xC0000112, 0xC0000113
    dd 0xC0000114, 0xC0000115, 0xC0000116, 0xC0000117
    dd 0x1D9, 0xC0000080, 0xC0000101, 0xC0000102, 0xC0000104
    dd 0xC0010010, 0xC001001A, 0xC0010200, 0xC0011022, 0x277
msr_count equ ($-msr_list)/4

align 8
gdt:
    dq 0
    dq 0x00CF9A000000FFFF    ; 0x08: 32-bit code, base 0, lim 4G
    dq 0x00CF92000000FFFF    ; 0x10: data
gdtdesc:
    dw gdtdesc - gdt - 1
    dd gdt
idtdesc:
    dw 256*8 - 1
    dd idt

section .text
global _start

%macro PUTS 1
    local %%str, %%lp, %%done
    jmp %%str
%%str: db %1, 0
%%str_end:
    jmp %%lp
%%lp:
    mov al, [%%lp - (%%str_end - %%str)] ; placeholder — see corrected macro below
    jmp %%done
%%done:
%endmacro

; simpler: use a function
puts:
    ; esi = NUL-terminated string
    push eax
    push edx
.l:
    lodsb
    test al, al
    jz .d
    mov dx, 0x402
    out dx, al
    jmp .l
.d:
    pop edx
    pop eax
    ret

hex32:
    ; eax = value
    push eax
    push ebx
    push ecx
    mov ebx, eax
    mov ecx, 8
.l:
    rol ebx, 4
    mov al, bl
    and al, 0x0F
    cmp al, 10
    jb .dig
    add al, 'A' - 10
    jmp .o
.dig:
    add al, '0'
.o:
    mov dx, 0x402
    out dx, al
    loop .l
    pop ecx
    pop ebx
    pop eax
    ret

hex64:
    ; edx:eax
    push eax
    mov eax, edx
    call hex32
    pop eax
    call hex32
    ret

_start:
    cli
    mov esp, stack_top
    lgdt [gdtdesc]
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    mov eax, 0x08
    push eax
    push dword flush
    retf
flush:
    ; build IDT gates: vector 6 (#UD) and 13 (#GP), 32-bit interrupt gates
    mov eax, ud_handler
    mov word [idt + 6*8], ax
    mov word [idt + 6*8 + 2], 0x08
    mov word [idt + 6*8 + 4], 0x8F00
    shr eax, 16
    mov word [idt + 6*8 + 6], ax
    mov eax, gp_handler
    mov word [idt + 13*8], ax
    mov word [idt + 13*8 + 2], 0x08
    mov word [idt + 13*8 + 4], 0x8F00
    shr eax, 16
    mov word [idt + 13*8 + 6], ax
    lidt [idtdesc]

    mov esi, s_start
    call puts

    xor ebp, ebp
.next:
    cmp ebp, msr_count
    jge .vmm
    mov ecx, [msr_list + ebp*4]
    mov eax, ecx
    call hex32
    mov esi, s_sep
    call puts
    xor eax, eax
    xor edx, edx
    rdmsr
    call hex64
    mov esi, s_nl
    call puts
    inc ebp
    jmp .next

.vmm:
    mov esi, s_vmm
    call puts
    vmmcall
    mov esi, s_nl
    call puts
    mov esi, s_done
    call puts
.h:
    cli
    hlt
    jmp .h

; ---- #GP handler: print "#GP! " and skip the faulting instruction ----
gp_handler:
    push eax
    push edx
    push esi
    mov esi, s_gp
    call puts
    pop esi
    mov eax, [esp + 12]        ; faulting EIP
    mov edx, [eax]
    call .skip
    mov [esp + 12], eax
    pop edx
    pop eax
    iret
.skip:
    cmp dl, 0x0F
    jne .one
    cmp dh, 0x32               ; rdmsr
    je .two
    cmp dh, 0x30               ; wrmsr
    je .two
    cmp dh, 0x01               ; vmmcall 0F 01 D9
    je .three
    jmp .two
.one:
    add eax, 1
    ret
.two:
    add eax, 2
    ret
.three:
    add eax, 3
    ret

; ---- #UD handler ----
ud_handler:
    push eax
    push edx
    push esi
    mov esi, s_ud
    call puts
    pop esi
    mov eax, [esp + 12]
    mov edx, [eax]
    call gp_handler.skip
    mov [esp + 12], eax
    pop edx
    pop eax
    iret

section .data
s_start: db "MSRPROBE-START", 10, 0
s_sep:   db " : ", 0
s_nl:    db 10, 0
s_gp:    db "#GP! ", 0
s_ud:    db "#UD! ", 0
s_vmm:   db "VMMCALL: ", 0
s_done:  db "MSRPROBE-DONE", 10, 0

_end_of_data:
section .bss
_end_of_bss:
