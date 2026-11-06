#!/usr/bin/env python3
"""WP20 G2 — THE NEWBUS DEVCLASS FIRST-INSERT LAZY-INIT (the user's plan #2)
          (crash 0xffffffff9e6a2535, CR2=0x0 WRITE — the subr_bus registry)

CASCADE (right after the GEOM unlock, IDX 735+): the first devclass
  registration runs devclass_find_internal(create=1) @0x9e6a2470:

    0x9e6a248a  lea rbx,[HEAD 0x9FE84160]      ; the global devclasses DLL
    0x9e6a24a0  mov rbx,[rbx]                  ; walk: obj->next @ +0x0
    ...         strcmp(obj->name(+0x28), sought) loop
    0x9e6a24c6  <create>: malloc(len+0x59)     ; obj, name inline @ +0x58
    0x9e6a252a  mov [rbx],0                    ; obj->next = NULL (new tail)
    0x9e6a2531  mov [rbx+8],rcx                ; obj->prev = old TAIL
    0x9e6a2535  mov [rcx],rbx                  <<< CR2=0x0: old TAIL == NULL
    0x9e6a2538  inc dword [COUNT 0x9FE84131]
    0x9e6a253e  mov [TAIL 0x9FE84168],rbx      ; TAIL = obj

  The wiped cold-boot .data leaves HEAD=TAIL=NULL; the DESIGNED first
  insert writes the new obj into the HEAD global itself (0x9FE84160).

THE USER'S FIX (verbatim): rcx==NULL -> lazy-init the head pair — the
  new object becomes the FIRST element through the HEAD global; after
  that the DLL links naturally (later inserts take the real old tail).

  Also prints the 'random: entropy device external interface' stage
  right after (the randomdev devclass registration follows).
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"

SLOT = 0x9E402B00                    # WP20 slot ledger (after G1: no slot)
S = 0x9E6A2535                       # mov [rcx],rbx  (3B) + inc 'ff 05' (2B)
CONT = 0xFFFFFFFF9E6A253E            # mov [TAIL],rbx (intact continuation)
HEAD = 0xFFFFFFFF9FE84160            # the devclasses HEAD global
CNT = 0xFFFFFFFF9FE84131             # the devclasses COUNT global

OLD = bytes.fromhex("488919" + "ff05")

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

C = f"""
    test rcx, rcx
    jnz  have_tail
    movabs rcx, {HEAD:#x}
have_tail:
    mov qword ptr [rcx], rbx
    movabs rax, {CNT:#x}
    inc dword ptr [rax]
    jmp  {CONT:#x}
"""

code = asm(C, SLOT)
print(f"slot {SLOT:#x}: {len(code):#x}B  hook {S:#x} (5B)")
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
    img[off:off+len(OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True)

print("--- devclass-list first-insert lazy-init (slot 0x9E402B00) ---")
for i in md.disasm(code, SLOT):
    print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print("OK WP20-G2: devclass first-insert lazy-init (@0x9E6A2535 -> slot 0x9E402B00)")
