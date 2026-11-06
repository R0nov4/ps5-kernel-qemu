#!/usr/bin/env python3
"""WP18 #16 — the zone limit-setter-2 NULL-zone guard (slot @0x9E402600)
          (crash 0xffffffff9e82d3fa, CR2=0x68 READ).

The zone-setup SYSINIT family's second stats/limit setter:
    fn 0x9e82d3f0: push rbp; push r15; push r14; push rbx; push rax;
    0x9e82d3fa  mov rax, [rdi+0x68]    ; the zone's keg   <<< CR2=0x68 (zone=NULL)
    0x9e82d3fe  mov rbx, rsi           ; the value
    0x9e82d401  test rax,rax; je -> xor r15d,r15d   ; keg==NULL
    0x9e82d40f  lea r14, [r15+0x18]    ; <- NULL+0x18 — the keg==NULL path is
                                       ;    NOT NULL-safe downstream either
    ... mtx_lock([r15+0x18]); [r15+0xa0]=rbx; mtx_unlock ...

FIX — the LOCAL GUARD: hook [0x9e82d3fa, 0x9e82d401) (7B: 'mov
  rax,[rdi+0x68]' + 'mov rbx,rsi'):
    rdi == 0  -> the replicated 5-push epilogue (add rsp,8; pop rbx;
                 pop r14; pop r15; pop rbp; ret) — a pure no-op setter;
    rdi != 0  -> replay both; jmp 0x9e82d401 (the designed walk).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E402600
S = 0x9E82D3FA                       # mov rax,[rdi+0x68]; mov rbx,rsi (7B)
CONT = 0xFFFFFFFF9E82D401            # test rax,rax

OLD = bytes.fromhex("488b47684889f3")

C = f"""
    test rdi, rdi
    jz   nullzone
    mov  rax, qword ptr [rdi + 0x68]
    mov  rbx, rsi
    jmp  {CONT:#x}
nullzone:
    add  rsp, 8
    pop  rbx
    pop  r14
    pop  r15
    pop  rbp
    ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

code = asm(C, SLOT)
print(f"slot 0x{SLOT:x}: {len(code):#x}B  hook {S:#x} ({len(OLD)}B)")
assert len(code) <= 0x80

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

off = S - KTEXT
site = bytes(img[off:off+len(OLD)])
if site[:1] == b"\xe9":
    rel_expect = SLOT - (S + 5)
    if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
        print(f"FAIL site {S:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
    print(f"site {S:#x}: already hooked to slot {SLOT:#x} (idempotent rewrite)")
    hooked = True
else:
    if site != OLD:
        print(f"FAIL site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
    hooked = False

off = SLOT - KTEXT
cur = bytes(img[off:off+len(code)])
if not all(b == 0xCC for b in cur) and cur != code:
    print(f"FAIL slot {SLOT:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)
print("site + slot assertions OK")

img[off:off+len(code)] = code
if not hooked:
    rel = SLOT - (S + 5)
    off = S - KTEXT
    img[off:off+len(OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD) - 5)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- zone limit-setter-2 NULL-zone guard (slot 0x9E402600) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
sz = len(img)
print(f"image size: {sz}")
assert sz == 65224704, "SIZE MISMATCH"
print("OK WP18#16: zone limit-setter-2 NULL-zone guard (local guard @0x9E402600)")
