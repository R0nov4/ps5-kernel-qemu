#!/usr/bin/env python3
"""WP20 G9 — THE DMEM + mDBG-TABLE + DCE FAMILY (the user's plan #9)
          [5 local guards: 1 in-place je retarget + 4 caves]

GUARD A — dmem_register_device (the user's verbatim site 0x9e7c0f13):
  (panic 'dmem_register_device: failed to find tmpmap page')
    fn 0x9e7c0ae0:
    0x9e7c0c62  call 0x9e8f33b0                  ; alloc(0x200000,...) — the
    0x9e7c0c67  [r12+rbx+0x68] = rax             ;   tmpmap page (the designed
    0x9e7c0c6c  test rax, rax                    ;   NULL: the empty domain lists)
    0x9e7c0c6f  je 0x9e7c0f48                    ;   -> the panic stub
    0x9e7c0f13  <the fn's OWN epilogue>: add rsp,0x18; pop rbx..r15; pop rbp; ret
  FIX: je retarget 0x9e7c0c6f -> 0x9e7c0f13 (the fn's epilogue — the
  designed tolerance: a NULL at a registration alloc takes the fn's own
  exit; the subsystem simply does not come up; the march walks on).

GUARDS B/C/D — the mDBG service-table trio (the user's verbatim sites
  0x9f070220 / 0x9f070370 / 0x9f0704d0, global [0xa21e31e0]):
  (Fatal trap 12 @ 0xffffffff9e8b71bc CR2=0x20 and @ 0x9f0704e2 CR2=0x0)
    All three fns load the mDBG service-context table from
    [0xa21e31e0] — NULL on this boot (the mDBG runtime never
    initialized under QEMU) — then lock/deref it.
  FIX: entry guards — [0xa21e31e0]==NULL -> the designed 'no service'
    answer (xor eax,eax / mov eax,0xc) and plain ret; otherwise the
    full prologue replays and the designed body runs.  Verified in the
    image: all three sites RIP-relative-resolve to 0xa21e31e0.

GUARD E — the dce module (the user's verbatim site 0x9ea84ff0):
  (panic 'dce-proc[3388]:panic:0x10' — the dce MOD_LOAD body is a
   blind call sequence of subsystem inits, each a fail-safe panicker
   when its kthread/alloc answers the designed NULL/error 12)
  FIX: the MOD_LOAD body entry answers its designed ENOMEM:
    mov eax, 0xc ; ret  — module_register_init prints 'MOD_LOAD (dce)
    error 12' and the walker marches on.
"""
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

KTEXT = 0x9E3F0000
IMG = "./kit_build/wp3_boot/kernel_raw.bin"
TBL = 0xFFFFFFFFA21E31E0                     # the mDBG service-context table

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        print(f"ASM FAILED @ {base:#x}"); sys.exit(1)
    return bytes(enc)

img = bytearray(open(IMG, "rb").read())
assert len(img) == 65224704, f"IMAGE SIZE CORRUPT ON DISK: {len(img)} — rebuild first"

# ---------------- GUARD A: dmem tmpmap je retarget (in place) ------------------
S_A = 0x9E7C0C6F
OLD_A = bytes.fromhex("0f84d3020000")        # je 0x9e7c0f48 (the panic stub)
NEW_A = bytes.fromhex("0f849e020000")        # je 0x9e7c0f13 (the fn's epilogue)
off = S_A - KTEXT
site = bytes(img[off:off+6])
if site == NEW_A:
    print(f"guard A {S_A:#x}: already retargeted (idempotent)")
elif site == OLD_A:
    img[off:off+6] = NEW_A
    print(f"OK guard A: dmem tmpmap je -> the fn epilogue @ {S_A:#x}")
else:
    print(f"FAIL guard A {S_A:#x}: {site.hex()}"); sys.exit(1)

def cave(SLOT, S, OLD, code, label):
    off = S - KTEXT
    site = bytes(img[off:off+len(OLD)])
    if site[:1] == b"\xe9":
        rel_expect = SLOT - (S + 5)
        if site[:5] != b"\xe9" + rel_expect.to_bytes(4, "little", signed=True):
            print(f"FAIL {label} site {S:#x} hooked elsewhere: {site[:5].hex()}"); sys.exit(1)
        hooked = True
    else:
        if site != OLD:
            print(f"FAIL {label} site {S:#x}: {site.hex()} != {OLD.hex()}"); sys.exit(1)
        hooked = False
    off2 = SLOT - KTEXT
    cur = bytes(img[off2:off2+len(code)])
    if not all(b == 0xCC for b in cur) and cur != code:
        print(f"FAIL {label} slot {SLOT:#x} not pristine CC: {cur[:16].hex()}"); sys.exit(1)
    img[off2:off2+len(code)] = code
    if not hooked:
        rel = SLOT - (S + 5)
        img[off:off+len(OLD)] = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\x90" * (len(OLD) - 5)
    print(f"--- {label} (slot {SLOT:#x}) ---")
    for i in md.disasm(code, SLOT):
        print(f"  {i.address:#x}  {i.bytes.hex():<26} {i.mnemonic} {i.op_str}")
    print(f"OK {label}: hook {S:#x} -> slot {SLOT:#x}")

# ---------------- GUARD B: mDBG service-call 0x9f070220 (cave) -----------------
SLOT_B = 0x9E403080
S_B = 0x9F070220                              # 13B: 5 pushes + mov ebx,edi
OLD_B = bytes.fromhex("554889e5" + "4157" + "4156" + "4154" + "53" + "89fb")
CONT_B = 0xFFFFFFFF9F07022D                   # mov rdi,[0xa21e31e0] (the designed body)

C_B = f"""
    movabs rax, {TBL:#x}
    cmp  qword ptr [rax], 0
    jne  live_b
    xor  eax, eax
    ret
live_b:
    push rbp
    mov  rbp, rsp
    push r15
    push r14
    push r12
    push rbx
    mov  ebx, edi
    jmp  {CONT_B:#x}
"""

code_b = asm(C_B, SLOT_B)
assert len(code_b) <= 0x80
cave(SLOT_B, S_B, OLD_B, code_b, "mDBG service-call NULL-table guard")

# ---------------- GUARD C: mDBG dispatcher 0x9f070370 (cave) -------------------
SLOT_C = 0x9E403100
S_C = 0x9F070370                              # 6B: push rbp; mov rbp,rsp; push r15
OLD_C = bytes.fromhex("554889e5" + "4157")
RESUME_C = 0xFFFFFFFF9F070376                 # push r14 (clean boundary)

C_C = f"""
    movabs rax, {TBL:#x}
    cmp  qword ptr [rax], 0
    jne  live_c
    mov  eax, 0xc
    ret
live_c:
    push rbp
    mov  rbp, rsp
    push r15
    jmp  {RESUME_C:#x}
"""

code_c = asm(C_C, SLOT_C)
assert len(code_c) <= 0x80
cave(SLOT_C, S_C, OLD_C, code_c, "mDBG dispatcher NULL-table guard")

# ---------------- GUARD D: mDBG wrapper 0x9f0704d0 (cave) ----------------------
SLOT_D = 0x9E403180
S_D = 0x9F0704D0                              # 11B: prologue + the table load
OLD_D = bytes.fromhex("554889e5" + "488b05052d1703")
CONT_D = 0xFFFFFFFF9F0704DB                   # mov rcx,rdx (the designed body)

C_D = f"""
    movabs r10, {TBL:#x}
    mov    rax, qword ptr [r10]
    test   rax, rax
    jz     no_service
    push   rbp
    mov    rbp, rsp
    jmp    {CONT_D:#x}
no_service:
    xor    eax, eax
    ret
"""

code_d = asm(C_D, SLOT_D)
assert len(code_d) <= 0x80
cave(SLOT_D, S_D, OLD_D, code_d, "mDBG wrapper NULL-table guard")

# ---------------- GUARD E: the dce MOD_LOAD body (cave) ------------------------
SLOT_E = 0x9E403200
S_E = 0x9EA84FF0                              # 6B: push rbp; mov rbp,rsp; push rbx; push rax
OLD_E = bytes.fromhex("554889e5" + "5350")

C_E = """
    mov  eax, 0xc
    ret
"""

code_e = asm(C_E, SLOT_E)
assert len(code_e) <= 0x80
cave(SLOT_E, S_E, OLD_E, code_e, "dce MOD_LOAD ENOMEM tolerance")

open(IMG, "wb").write(img)
assert len(img) == 65224704, "SIZE MISMATCH"
print("OK WP20-G9: dmem + mDBG trio + dce family (5 guards) — the deep-march "
      "module storm tolerated")
