#!/usr/bin/env python3
"""Scan pmap region for TAILQ_INSERT_TAIL patterns (mov [E+0x10],T ; mov [T],E)."""
import capstone
DUMP = "./ps5/dump13/kernel-13.60-live.bin"
IMG = open(DUMP, "rb").read()
KTEXT = 0xffffffff9e3f0000
md = capstone.Cs(capstone.C86 if False else capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

LO, HI = 0xffffffff9ecc0000, 0xffffffff9ed10000   # pmap region
code = IMG[LO - KTEXT : HI - KTEXT]
insns = list(md.disasm(code, LO))
print(f"disassembled {len(insns)} insns in [{LO:#x},{HI:#x})")

def regs(i):
    return {x for op in i.operands for x in ([op.reg] if op.type == capstone.x86.X86_OP_REG else [])}

hits = 0
for k in range(len(insns) - 1):
    a, b = insns[k], insns[k+1]
    if a.mnemonic != "mov" or b.mnemonic != "mov":
        continue
    # a: mov [E+0x10], T   (mem dst w/ disp 0x10, reg src)
    # b: mov [T], E        (mem dst no disp, reg src)
    try:
        ao = a.operands; bo = b.operands
    except Exception:
        continue
    if len(ao) != 2 or len(bo) != 2: continue
    if ao[0].type != capstone.x86.X86_OP_MEM or ao[1].type != capstone.x86.X86_OP_REG: continue
    if bo[0].type != capstone.x86.X86_OP_MEM or bo[1].type != capstone.x86.X86_OP_REG: continue
    if ao[0].mem.disp != 0x10 or ao[0].mem.index != 0: continue
    if bo[0].mem.disp != 0 or bo[0].mem.index != 0: continue
    E, T = ao[0].mem.base, ao[1].reg
    if bo[1].reg != E or bo[0].mem.base != T: continue
    # look back 3 insns for load of T from [H+0x40] or lea T from [H+0x38]
    ctx = ""
    for j in range(max(0, k-3), k):
        p = insns[j]
        if p.mnemonic == "mov" and "0x40]" in p.op_str and p.op_str.split(",")[-1].strip().lstrip("e").startswith(("r","c","a","d","b","s")):
            ctx += f"  <- {p.mnemonic} {p.op_str}"
    print(f"{a.address:#x}: {a.mnemonic} {a.op_str} ; {b.mnemonic} {b.op_str}{ctx}")
    hits += 1
print(f"total candidate INSERT sites: {hits}")
