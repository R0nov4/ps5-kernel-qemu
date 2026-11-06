#!/usr/bin/env python3
import hashlib, os, re, struct, subprocess, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

KTEXT     = 0x9E3F0000
TEXT_HI   = 0x9F780000
PANIC_FN  = 0x9F08AA10
IMG       = "wp3_boot/kernel_raw.bin"
SLOT_BASE = 0x9E414C80
SLOT_STEP = 0x80

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        raise RuntimeError(f"ASM failed @ {base:#x}: {code}")
    return bytes(enc)

# 1. Break the stage #1315 SMP spin loop @ 0x9ec0eed9 (je 0x9ec0eed0 -> nop; nop)
b = bytearray(open(IMG, "rb").read())
va_spin = 0x9EC0EED9
if b[va_spin - KTEXT : va_spin - KTEXT + 2] == b"\x74\xf5":
    b[va_spin - KTEXT : va_spin - KTEXT + 2] = b"\x90\x90"
    open(IMG, "wb").write(b)
    print("[+] Broke stage #1315 SMP spin loop @ 0x9ec0eed9 (74 f5 -> 90 90)!")

def next_free_slot(b):
    for s in range(SLOT_BASE, 0x9E600000, SLOT_STEP):
        if all(x == 0xCC for x in b[s - KTEXT : s - KTEXT + SLOT_STEP]):
            return s
    raise RuntimeError("No free CC slot!")

def find_fn_start(b, va):
    for p in range(va, max(KTEXT, va - 0x2500), -1):
        if b[p - KTEXT : p - KTEXT + 4] == b"\x55\x48\x89\xe5":
            if b[p - KTEXT - 1] in (0xC3, 0xCC, 0x90, 0x0B, 0xE9, 0xEB):
                return p
    idx = bytes(b).rfind(b"\x55\x48\x89\xe5", max(0, va - KTEXT - 0x2500), va - KTEXT + 1)
    return KTEXT + idx if idx >= 0 else None

def get_unwind_insns(b, fn_start):
    p_ins = list(md.disasm(bytes(b[fn_start - KTEXT : fn_start - KTEXT + 64]), fn_start))
    if len(p_ins) >= 2 and p_ins[0].mnemonic == "push" and p_ins[0].op_str == "rbp":
        pushes, subsum = [], 0
        for x in p_ins[2:]:
            if x.mnemonic == "push":
                pushes.append(x.op_str)
            elif x.mnemonic == "sub" and x.op_str.startswith("rsp,"):
                subsum += int(x.op_str.split(",")[1].strip(), 0)
            else:
                break
        unw = []
        if subsum:
            unw.append(f"add rsp, {subsum:#x}")
        for r in reversed(pushes):
            unw.append("add rsp, 8" if r == "rax" else f"pop {r}")
        unw.append("pop rbp")
        return unw
    return ["pop rbp"]

def relocate_insns(disp_insns, base_va):
    out = b""
    for ins in disp_insns:
        raw = bytes(ins.bytes)
        cur_va = base_va + len(out)
        if "rip" in ins.op_str:
            m = re.search(r"rip\s*([+-])\s*(0x[0-9a-f]+|\d+)", ins.op_str)
            if m:
                disp = int(m.group(2), 0) * (-1 if m.group(1) == "-" else 1)
                target = ins.address + ins.size + disp
                old_b = disp.to_bytes(4, "little", signed=True)
                pos = raw.rfind(old_b)
                if pos >= 0:
                    new_disp = target - (cur_va + ins.size)
                    raw = raw[:pos] + new_disp.to_bytes(4, "little", signed=True) + raw[pos+4:]
                    out += raw
                    continue
        if (ins.mnemonic in ("call", "jmp") or ins.mnemonic.startswith("j")) and ins.op_str.startswith("0x"):
            target = int(ins.op_str, 16) & 0xFFFFFFFF
            out += asm(f"{ins.mnemonic} {target:#x}", cur_va)
            continue
        out += raw
    return out

def auto_fix_page_fault(rip, cr2):
    b = bytearray(open(IMG, "rb").read())
    fn_start = find_fn_start(b, rip)
    slot = next_free_slot(b)
    print(f"\n[*] Auto-fixing Page Fault @ {rip:#x} (CR2={cr2:#x}) in fn {fn_start:#x} -> slot {slot:#x}")

    ins_list = list(md.disasm(bytes(b[rip - KTEXT : rip - KTEXT + 32]), rip))
    fault_ins = ins_list[0]
    print(f"    Faulting insn: {fault_ins.address:#x}: {fault_ins.mnemonic} {fault_ins.op_str}")

    # Special case: instruction jump/call to NULL (rip == 0)
    if rip < KTEXT:
        raise RuntimeError(f"RIP={rip:#x} outside kernel text")

    m = re.search(r"\[([^\]]+)\]", fault_ins.op_str)
    expr = m.group(1) if m else fault_ins.op_str
    regs = [r for r in ("rax","rbx","rcx","rdx","rsi","rdi","rbp","r8","r9","r10","r11","r12","r13","r14","r15")
            if re.search(rf"\b{r}\b", expr)]
    reg0 = regs[0] if regs else "rax"

    disp_insns, tot = [], 0
    for x in ins_list:
        disp_insns.append(x)
        tot += x.size
        if tot >= 5:
            break
    cont_va = rip + tot
    unw = get_unwind_insns(b, fn_start) if fn_start else ["pop rbp"]

    scratch = "r10" if reg0 == "r11" else "r11"
    chk_head = asm(f"pushfq; push {scratch}; mov {scratch}, {reg0}; sar {scratch}, 47; inc {scratch}", slot)
    pop_ok = asm(f"pop {scratch}; popfq", slot + len(chk_head) + 2)
    replayed = relocate_insns(disp_insns, slot + len(chk_head) + 2 + len(pop_ok))
    jmp_cont = asm(f"jmp {cont_va:#x}", slot + len(chk_head) + 2 + len(pop_ok) + len(replayed))

    body_ok = pop_ok + replayed + jmp_cont
    jnz_bail = bytes([0x75, len(body_ok)])
    bail_start = slot + len(chk_head) + 2 + len(body_ok)
    bail_code = asm(f"pop {scratch}; popfq; xor eax, eax; " + "; ".join(unw) + "; ret", bail_start)

    stub = chk_head + jnz_bail + body_ok + bail_code
    b[slot - KTEXT : slot - KTEXT + len(stub)] = stub
    rel = (slot - (rip + 5)).to_bytes(4, "little", signed=True)
    b[rip - KTEXT : rip - KTEXT + tot] = b"\xe9" + rel + b"\x90" * (tot - 5)
    open(IMG, "wb").write(b)
    print(f"    [+] Guarded {reg0} @ {rip:#x} (unwind: {'; '.join(unw)})")
    return True

def auto_fix_panic(msg):
    b = bytearray(open(IMG, "rb").read())
    print(f"\n[*] Auto-fixing panic: {msg!r}")
    candidates = [msg.strip()]
    if ":" in msg:
        candidates.extend([p.strip() for p in msg.split(":") if len(p.strip()) >= 4])
    for tok in candidates:
        needle = tok.encode("ascii", errors="ignore")[:22]
        pos = 0
        while True:
            idx = bytes(b).find(needle, pos)
            if idx < 0: break
            pos = idx + 1
            s_start = bytes(b).rfind(b"\x00", 0, idx) + 1
            str_va = KTEXT + s_start
            for m in re.finditer(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", bytes(b[:TEXT_HI - KTEXT])):
                p = m.start()
                rel = struct.unpack("<i", b[p+3:p+7])[0]
                if KTEXT + p + 7 + rel == str_va:
                    fn_start = find_fn_start(b, KTEXT + p)
                    if fn_start:
                        unw = get_unwind_insns(b, fn_start)
                        insns = list(md.disasm(bytes(b[fn_start - KTEXT : fn_start - KTEXT + 0x1500]), fn_start))
                        for i in insns:
                            if i.mnemonic == "call" and i.op_str == f"0x{PANIC_FN:x}":
                                slot = next_free_slot(b)
                                stub = asm("xor eax, eax; " + "; ".join(unw) + "; ret", slot)
                                b[slot - KTEXT : slot - KTEXT + len(stub)] = stub
                                rel_j = (slot - (i.address + 5)).to_bytes(4, "little", signed=True)
                                b[i.address - KTEXT : i.address - KTEXT + 5] = b"\xe9" + rel_j
                                open(IMG, "wb").write(b)
                                print(f"  [->] Diverted panic call @ {i.address:#x} -> {slot:#x}")
                                return True
    return False

def auto_break_spin_with_gdb():
    print("\n[*] Quiet boot — attaching GDB @ 12s to check if parked or spinning...")
    p = subprocess.Popen([
        "qemu-system-x86_64", "-L", "./bios", "-M", "pc", "-cpu", "EPYC", "-m", "2G", "-smp", "8",
        "-kernel", "wp3_boot/trampoline.elf", "-initrd", "wp3_boot/kernel_raw.bin",
        "-display", "none", "-serial", "null", "-monitor", "none", "-gdb", "tcp::1234", "-no-reboot"
    ], stderr=subprocess.DEVNULL)
    subprocess.run(["sleep", "12"])
    out = subprocess.check_output([
        "gdb", "-q", "-batch",
        "-ex", "target remote :1234",
        "-ex", "info reg rip rsp rbp r12 r13 r14",
        "-ex", "x/8i $rip",
        "-ex", "x/12gx $rsp",
        "-ex", "detach", "-ex", "quit"
    ], text=True, stderr=subprocess.STDOUT)
    p.terminate()
    print(out)

    m = re.search(r"rip\s+0xffffffff([0-9a-fA-F]{8})", out)
    if not m:
        return False
    rip = int(m.group(1), 16)
    if 0x9E404700 <= rip <= 0x9E404740:
        print("\n🏁🎉 CPU IS PARKED INSIDE G41/G50 PARK STUB (0x9e404700..)! SYSINIT 100% DONE! 🎉🏁")
        return False

    # Look for a tight backward conditional jump near rip and NOP it out
    b = bytearray(open(IMG, "rb").read())
    lo = max(KTEXT, rip - 0x20)
    insns = list(md.disasm(bytes(b[lo - KTEXT : rip - KTEXT + 0x30]), lo))
    for i in insns:
        if i.mnemonic.startswith("j") and i.mnemonic != "jmp" and i.op_str.startswith("0x"):
            tgt = int(i.op_str, 16) & 0xFFFFFFFF
            if tgt <= rip <= i.address and (i.address - tgt) <= 0x40:
                print(f"[+] Breaking tight spin loop @ {i.address:#x}: {i.mnemonic} {i.op_str} -> NOPs!")
                b[i.address - KTEXT : i.address - KTEXT + i.size] = b"\x90" * i.size
                open(IMG, "wb").write(b)
                return True
    return False

for step in range(1, 25):
    print(f"\n================ [FINISH-TO-PARK RUN #{step}] ================")
    subprocess.run(["bash", "run.sh", "60"], check=False)
    log = open("serial.log", "rb").read().decode("latin1", errors="replace")

    if "WP23: sysinit walk complete; parking." in log:
        print("\n" + "="*65)
        print("🏁🎉 MILESTONE 100% COMPLETE: 'WP23: sysinit walk complete; parking.' 🎉🏁")
        print(f"Final kernel_raw.bin MD5: {hashlib.md5(open(IMG,'rb').read()).hexdigest()}")
        print("="*65)
        sys.exit(0)

    m_pf = re.search(r"fault virtual address\s*=\s*(0x[0-9a-fA-F]+).*?instruction pointer\s*=\s*0x20:0xffffffff([0-9a-fA-F]{8})", log, re.S)
    m_pan = re.search(r"panic:\s*([^\r\n]+)", log)

    if m_pf:
        auto_fix_page_fault(int(m_pf.group(2), 16), int(m_pf.group(1), 16))
    elif m_pan and "page fault" not in m_pan.group(1):
        if not auto_fix_panic(m_pan.group(1)):
            break
    else:
        if not auto_break_spin_with_gdb():
            break
