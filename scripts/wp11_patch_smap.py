#!/usr/bin/env python3
"""WP11 fix #4 (SYSTEMIC) — reserve the seed area in the multiboot SMAP.

Root cause of the ghost-object cascade: the kernel's page allocator hands out
phys pages from [0x3F000000, 0x40000000) (the seed area: W1 bump objects,
W4 bitmap, W6 list-tail, W8 PD) because QEMU's mbi mmap lists it as RAM.
UMA zone objects then land on never-initialized seed pages (zero mtx locks,
NULL callbacks) -> the 0x9e8b6c71 / call-NULL crash family.

Fix: inject a `mmap_fix` routine into the trampoline (appended past the LOAD
segment's current filesz, VA 0x10424E) that rewrites the 6-entry mbi mmap:
    RAM      [0x00100000, 0x3F000000)     (entry 2, shrunk)
    RESERVED [0x3F000000, 0x40000000)     (entry 3, was ACPI-resv)
    RAM      [0x40000000, 0x7FFE0000)     (entry 4, was >4GB-resv)
    RESERVED [0x7FFE0000, 0x80000000)     (entry 5, was >4GB-resv)
The first NOPed rsdp_scan call site (file 0x4E8D) becomes `call mmap_fix`.
"""
import struct
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_32

ELF = "./kit_build/wp3_boot/trampoline.elf"
NEWCODE_VA = 0x10424E          # file 0x524E = end of current filesz
CALL_SITE_FILE = 0x4E8D        # (VA 0x103E8D) first NOPed rsdp_scan call
CALL_SITE_VA = 0x103E8D

ROUTINE = """
pusha
mov eax, dword ptr [ebx + 0x30]
test eax, eax
jz done
mov edx, 8
scan:
cmp dword ptr [eax + 20], 1
jne next
cmp dword ptr [eax + 4], 0x100000
jne next
mov dword ptr [eax + 12], 0x3ef00000
mov dword ptr [eax + 28], 0x3f000000
mov dword ptr [eax + 36], 0x1000000
mov dword ptr [eax + 52], 0x40000000
mov dword ptr [eax + 60], 0x3ffe0000
mov byte ptr [eax + 68], 1
mov dword ptr [eax + 76], 0x7ffe0000
mov dword ptr [eax + 80], 0
mov dword ptr [eax + 84], 0x20000
mov dword ptr [eax + 88], 0
mov byte ptr [eax + 92], 2
jmp done
next:
add eax, 24
dec edx
jnz scan
done:
popa
ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_32)
enc, cnt = ks.asm(ROUTINE, NEWCODE_VA)
code = bytes(enc)
print(f"mmap_fix routine: {len(code)} bytes @ VA {NEWCODE_VA:#x} ({cnt} insns)")

elf = bytearray(open(ELF, "rb").read())

# 1. verify call site is the 5 NOPs from wp9_patch_trampoline
cur = bytes(elf[CALL_SITE_FILE:CALL_SITE_FILE + 5])
if cur != b"\x90" * 5:
    print(f"FAIL: call site @file {CALL_SITE_FILE:#x} is {cur.hex()}, expected 90x5")
    sys.exit(1)

# 2. write the routine at file offset 0x524E (just past current filesz;
#    clobbers the ELF section headers, which QEMU's multiboot loader ignores)
CODE_OFF = 0x524E
need = CODE_OFF + len(code)
if len(elf) < need:
    elf.extend(b"\x00" * (need - len(elf)))
elf[CODE_OFF:CODE_OFF + len(code)] = code

# 3. update the LOAD segment filesz/memsz (phdr at 0x34, 32-byte entries, 1 phdr)
p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
    struct.unpack_from("<IIIIIIII", elf, 0x34)
assert p_type == 1 and p_offset == 0x1000 and p_filesz == 0x424E
new_filesz = len(elf) - 0x1000
new_memsz = max(p_memsz, new_filesz)
struct.pack_into("<II", elf, 0x34 + 16, new_filesz, new_memsz)
print(f"LOAD filesz: {p_filesz:#x} -> {new_filesz:#x}, memsz {p_memsz:#x} -> {new_memsz:#x}")

# 4. write the call at the first rsdp_scan site
rel = NEWCODE_VA - (CALL_SITE_VA + 5)
call = b"\xe8" + struct.pack("<i", rel)
elf[CALL_SITE_FILE:CALL_SITE_FILE + 5] = call
print(f"call site @VA {CALL_SITE_VA:#x}: 90x5 -> {call.hex()} (rel {rel:+#x})")

open(ELF, "wb").write(elf)
print(f"patched -> {ELF} ({len(elf)} bytes)")
