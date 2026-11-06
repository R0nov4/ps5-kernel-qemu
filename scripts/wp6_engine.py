#!/usr/bin/env python3
"""wp6_engine.py — full disasm of the sscanf engine 0x9ea65a00..0x9ea66760;
find all jump-back edges into the stuck window 0x9ea65f60..0x9ea66060.
"""
import capstone

ELF = "./download/ps5_kernel_1360_reconstructed.elf"
T_OFF, T_SZ = 0x1000, 0xCC0000
T_VA = 0x9E3F0000
blob = open(ELF, "rb").read()
text = blob[T_OFF:T_OFF+T_SZ]

LO, HI = 0x9EA65A00, 0x9EA66760
STUCK_LO, STUCK_HI = 0x9EA65F60, 0x9EA66060
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

code = text[LO - T_VA: HI - T_VA]
insns = list(md.disasm(code, LO))
print(f"disassembled {len(insns)} instructions from {LO:#x} to {insns[-1].address + insns[-1].size:#x}")

# all jumps (conditional/unconditional/indirect) whose target lands in stuck window
print(f"\n=== edges INTO stuck window [{STUCK_LO:#x},{STUCK_HI:#x}) ===")
for i, ins in enumerate(insns):
    if ins.mnemonic.startswith("j") or ins.mnemonic == "loop":
        # direct rel32/rel8 targets
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_IMM:
                tgt = op.imm & 0xFFFFFFFFFFFFFFFF
                if STUCK_LO <= tgt < STUCK_HI:
                    print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}   ->  {tgt:#x}")

# print the stuck window itself with jump-table resolution
print(f"\n=== stuck window disasm ===")
JT = 0x9EA6604F + 7 + 0x10B0122  # lea rdx, [rip+0x10b0122] at 0x9ea6604f
print(f"jump table @ {JT:#x}")
import struct
def va2img(va):
    return va - T_VA
jt_off = va2img(JT)
entries = {}
for k in range(0x4E):
    disp = struct.unpack_from("<i", text, jt_off + 4*k)[0]
    entries[k] = JT + disp
for ins in insns:
    if STUCK_LO <= ins.address < STUCK_HI:
        print(f"  {ins.address:#x}: {' '.join(f'{b:02x}' for b in ins.bytes):<26} {ins.mnemonic} {ins.op_str}")

# where does the dispatch at 0x9ea6605d go for each char class?
print(f"\n=== dispatch targets (char -> target) ===")
for k in sorted(entries):
    ch = k + 0x2b
    c = chr(ch) if 32 <= ch < 127 else f"\\x{ch:02x}"
    print(f"  char {c!r} (0x{ch:02x}) -> {entries[k]:#x}")
