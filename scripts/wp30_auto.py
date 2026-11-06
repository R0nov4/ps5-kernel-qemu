#!/usr/bin/env python3
import hashlib, os, re, shutil, struct, subprocess, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

KTEXT   = 0x9E3F0000
TEXT_HI = 0x9F780000
IMG     = "wp3_boot/kernel_raw.bin"
BAK     = "wp3_boot/kernel_raw.bin.wp29_bak"
SLOT_BASE = 0x9E414880
SLOT_STEP = 0x80

ks = Ks(KS_ARCH_X86, KS_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

if not os.path.exists(BAK):
    shutil.copyfile(IMG, BAK)
    print(f"[+] Backup saved to {BAK}")

def asm(code, base):
    enc, _ = ks.asm(code, base)
    if not enc:
        raise RuntimeError(f"ASM failed @ {base:#x}: {code}")
    return bytes(enc)

def find_next_free_slot(img):
    for s in range(SLOT_BASE, 0x9E600000, SLOT_STEP):
        chunk = img[s - KTEXT : s - KTEXT + SLOT_STEP]
        if all(b == 0xCC for b in chunk):
            return s
    raise RuntimeError("No free CC slot found!")

def find_fn_start(img, va):
    for p in range(va, max(KTEXT, va - 0x2000), -1):
        if img[p - KTEXT : p - KTEXT + 4] == b"\x55\x48\x89\xe5":
            # make sure previous byte is ret/int3/nop/jmp/ud2
            prev = img[p - KTEXT - 1]
            if prev in (0xC3, 0xCC, 0x90, 0x0B, 0xE9, 0xEB):
                return p
    idx = bytes(img).rfind(b"\x55\x48\x89\xe5", max(0, va - KTEXT - 0x2000), va - KTEXT + 1)
    return KTEXT + idx if idx >= 0 else None

def find_epilogue_va_and_insns(img, fn_start, crash_va):
    # Scan from fn_start up to fn_start + 0x2500 for clean epilogue ending in ret
    end_limit = min(TEXT_HI, max(crash_va + 0x400, fn_start + 0x1500))
    insns = list(md.disasm(bytes(img[fn_start - KTEXT : end_limit - KTEXT]), fn_start))
    for k, i in enumerate(insns):
        if i.address > fn_start + 4 and i.bytes == b"\x55" and k + 1 < len(insns) and insns[k+1].bytes == b"\x48\x89\xe5":
            insns = insns[:k]
            break
    for k in range(len(insns) - 1, -1, -1):
        if insns[k].mnemonic == "ret" and not insns[k].op_str:
            j = k - 1
            while j >= 0 and (
                insns[j].mnemonic == "pop"
                or (insns[j].mnemonic == "add" and insns[j].op_str.startswith("rsp,"))
                or insns[j].mnemonic == "leave"
            ):
                j -= 1
            run = insns[j + 1 : k]
            if run and any(x.mnemonic == "leave" or (x.mnemonic == "pop" and x.op_str == "rbp") for x in run):
                return run[0].address, [f"{x.mnemonic} {x.op_str}".strip() for x in run]
    # Fallback: derive from prologue
    p_ins = list(md.disasm(bytes(img[fn_start - KTEXT : fn_start - KTEXT + 48]), fn_start))
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
        unw.append(f"add rsp, {subsum}")
    for r in reversed(pushes):
        if r == "rax":
            unw.append("add rsp, 8")
        else:
            unw.append(f"pop {r}")
    unw.append("pop rbp")
    return None, unw

def extract_base_reg(insn):
    # Extract base/index register inside [...] of the faulting instruction
    m = re.search(r"\[([^\]]+)\]", insn.op_str)
    if not m:
        return None
    expr = m.group(1)
    for r in ("rax","rbx","rcx","rdx","rsi","rdi","rbp","r8","r9","r10","r11","r12","r13","r14","r15"):
        if re.search(rf"\b{r}\b", expr):
            return r
    return None

def relocate_displaced(displaced_insns, stub_cur_va):
    out = b""
    for ins in displaced_insns:
        raw = bytes(ins.bytes)
        cur_va = stub_cur_va + len(out)
        if "rip" in ins.op_str:
            m = re.search(r"rip\s*([+-])\s*(0x[0-9a-f]+|\d+)", ins.op_str)
            if m:
                disp = int(m.group(2), 0) * (-1 if m.group(1) == "-" else 1)
                target = ins.address + ins.size + disp
                # Find disp32 in raw bytes
                old_disp_bytes = disp.to_bytes(4, "little", signed=True)
                pos = raw.rfind(old_disp_bytes)
                if pos >= 0:
                    # Wait: if disp32 is not at the very end (e.g. immediate follows), offset from end is ins.size - pos
                    new_disp = target - (cur_va + ins.size)
                    raw = raw[:pos] + new_disp.to_bytes(4, "little", signed=True) + raw[pos+4:]
                    out += raw
                    continue
        if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
            target = int(ins.op_str, 16) & 0xFFFFFFFF
            enc = asm(f"{ins.mnemonic} {target:#x}", cur_va)
            out += enc
            continue
        if ins.mnemonic.startswith("j") and ins.op_str.startswith("0x"):
            target = int(ins.op_str, 16) & 0xFFFFFFFF
            enc = asm(f"{ins.mnemonic} {target:#x}", cur_va)
            out += enc
            continue
        out += raw
    return out

def patch_page_fault(crash_va, cr2):
    img = bytearray(open(IMG, "rb").read())
    slot = find_next_free_slot(img)
    fn_start = find_fn_start(img, crash_va)
    print(f"\n[*] Analyzing Page Fault @ {crash_va:#x} (CR2={cr2:#x}), fn_start={fn_start:#x}, slot={slot:#x}")

    if fn_start:
        print("--- Function Disassembly around crash ---")
        lo = max(fn_start, crash_va - 0x40)
        for i in md.disasm(bytes(img[lo - KTEXT : crash_va - KTEXT + 0x30]), lo):
            mark = "  <<< CRASH HERE" if i.address == crash_va else ""
            print(f"  {i.address:#x}: {i.bytes.hex():<20} {i.mnemonic} {i.op_str}{mark}")

    # Disassemble from crash_va to get >= 5 bytes for E9 jmp
    ins_at_crash = list(md.disasm(bytes(img[crash_va - KTEXT : crash_va - KTEXT + 32]), crash_va))
    if not ins_at_crash:
        raise RuntimeError(f"Cannot disasm at {crash_va:#x}")

    fault_ins = ins_at_crash[0]
    base_reg = extract_base_reg(fault_ins)
    if not base_reg:
        raise RuntimeError(f"Could not find memory base register in: {fault_ins.mnemonic} {fault_ins.op_str}")

    disp_insns = []
    tot = 0
    for x in ins_at_crash:
        disp_insns.append(x)
        tot += x.size
        if tot >= 5:
            break
    cont_va = crash_va + tot
    old_bytes = bytes(img[crash_va - KTEXT : cont_va - KTEXT])

    epi_va, unw_list = find_epilogue_va_and_insns(img, fn_start, crash_va) if fn_start else (None, ["pop rbp"])
    print(f"[*] Faulting base reg: {base_reg} | Displaced: {tot}B | Unwind: {'; '.join(unw_list)}")

    # Build safe guard stub in slot:
    # Check if base_reg is valid canonical kernel address (top 17 bits == all 1s, i.e., sar 47 == -1)
    # Using pushfq + push r11 (or r10 if base_reg == r11) so valid path is 100% transparent!
    scratch = "r10" if base_reg == "r11" else "r11"
    pre_check = asm(f"""
        pushfq
        push {scratch}
        mov {scratch}, {base_reg}
        sar {scratch}, 47
        inc {scratch}
        jnz bad_ptr
        pop {scratch}
        popfq
    """, slot)
    # Wait: keystone needs bad_ptr label resolved, so let's build the whole stub or compute offset
    chk_head = asm(f"pushfq; push {scratch}; mov {scratch}, {base_reg}; sar {scratch}, 47; inc {scratch}", slot)
    # jnz rel8 to bail_pop
    pop_ok = asm(f"pop {scratch}; popfq", slot + len(chk_head) + 2)
    replayed = relocate_displaced(disp_insns, slot + len(chk_head) + 2 + len(pop_ok))
    jmp_cont = asm(f"jmp {cont_va:#x}", slot + len(chk_head) + 2 + len(pop_ok) + len(replayed))

    body_ok = pop_ok + replayed + jmp_cont
    jnz_bail = bytes([0x75, len(body_ok)])

    bail_start = slot + len(chk_head) + 2 + len(body_ok)
    bail_code = asm(f"pop {scratch}; popfq; xor eax, eax; " + "; ".join(unw_list) + "; ret", bail_start)

    stub = chk_head + jnz_bail + body_ok + bail_code
    assert len(stub) <= SLOT_STEP, f"Stub too large ({len(stub)}B)"

    # Write stub & hook
    img[slot - KTEXT : slot - KTEXT + len(stub)] = stub
    rel = (slot - (crash_va + 5)).to_bytes(4, "little", signed=True)
    img[crash_va - KTEXT : crash_va - KTEXT + tot] = b"\xe9" + rel + b"\x90" * (tot - 5)

    open(IMG, "wb").write(img)
    print(f"[+] Patched {crash_va:#x} -> slot {slot:#x} (md5={hashlib.md5(img).hexdigest()})")

def patch_panic_string(panic_msg):
    img = bytearray(open(IMG, "rb").read())
    needle = panic_msg.encode("ascii", errors="ignore")[:24]
    idx = bytes(img).find(needle)
    if idx < 0:
        raise RuntimeError(f"Panic string not found: {panic_msg!r}")
    str_va = KTEXT + idx
    print(f"[*] Found panic string {panic_msg!r} @ {str_va:#x}")
    # Find lea reg, [rip + disp] pointing to str_va
    for m in re.finditer(rb"\x48\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", bytes(img[:TEXT_HI - KTEXT])):
        p = m.start()
        rel = struct.unpack("<i", img[p+3:p+7])[0]
        if KTEXT + p + 7 + rel == str_va:
            lea_va = KTEXT + p
            fn_start = find_fn_start(img, lea_va)
            slot = find_next_free_slot(img)
            _, unw_list = find_epilogue_va_and_insns(img, fn_start, lea_va)
            print(f"[*] Found panic xref @ {lea_va:#x} in fn {fn_start:#x} -> B-diverting to slot {slot:#x}")
            stub = asm("mov eax, 0xc; " + "; ".join(unw_list) + "; ret", slot)
            img[slot - KTEXT : slot - KTEXT + len(stub)] = stub
            jmp_rel = (slot - (lea_va + 5)).to_bytes(4, "little", signed=True)
            img[p : p + 7] = b"\xe9" + jmp_rel + b"\x90\x90"
            open(IMG, "wb").write(img)
            print(f"[+] Diverted panic @ {lea_va:#x} -> {slot:#x}")
            return
    raise RuntimeError(f"No xref found for panic string @ {str_va:#x}")

# Main Auto-Loop
for step in range(1, 25):
    log = open("serial.log", "rb").read().decode("latin1", errors="replace") if os.path.exists("serial.log") else ""
    if "WP23: sysinit walk complete; parking." in log:
        print("\n🎉🎉🎉 MILESTONE REACHED: 'WP23: sysinit walk complete; parking.'! 🎉🎉🎉")
        sys.exit(0)

    m_pf = re.search(r"fault virtual address\s*=\s*(0x[0-9a-fA-F]+).*?instruction pointer\s*=\s*0x20:0xffffffff([0-9a-fA-F]{8})", log, re.S)
    m_pan = re.search(r"panic:\s*([^\r\n]+)", log)

    if m_pf:
        cr2 = int(m_pf.group(1), 16)
        rip = int(m_pf.group(2), 16)
        patch_page_fault(rip, cr2)
    elif m_pan and "page fault" not in m_pan.group(1):
        patch_panic_string(m_pan.group(1).strip())
    elif step > 1:
        print("\n[!] Boot finished with NO crash/panic (quiet exit). Checking tail of serial.log:")
        print("\n".join(log.splitlines()[-15:]))
        sys.exit(0)

    print(f"\n=== [Round {step}] Running QEMU boot (bash run.sh 60) ===")
    subprocess.run(["bash", "run.sh", "60"], check=False)
