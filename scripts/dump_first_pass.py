#!/usr/bin/env python3
"""First-pass empirical mining of the public PS5 13.60 live kernel dump.
Adjudicates disputes between external consultations using ground-truth bytes.
Layout (from repo JSON, SHA-256 verified):
  text: file[0:13,369,344]        @ 0xffffffff9e3f0000
  data: file[0xcc0000:103,546,880] @ 0xffffffff9f0b0000  (688 zero pages)
"""
import json, hashlib, struct, math, re
from collections import Counter

DUMP = "./ps5/dump13/kernel-13.60-live.bin"
TEXT_SIZE, DATA_OFF, DATA_SIZE = 13_369_344, 0xCC0000, 90_177_536
TEXT_BASE, DATA_BASE = 0xFFFFFFFF9E3F0000, 0xFFFFFFFF9F0B0000

blob = open(DUMP, "rb").read()
assert len(blob) == 103_546_880, len(blob)
text, data = blob[:TEXT_SIZE], blob[DATA_OFF:]

findings = {}

# ---------- 0. sanity: is text really code? ----------
def entropy(b):
    c = Counter(b); n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())
e_text, e_data = entropy(text[:1 << 20]), entropy(data[:1 << 20])
print(f"[0] entropy: text={e_text:.3f} (compiled code ~6.2-6.8)  data={e_data:.3f}")
findings["entropy_text"] = round(e_text, 3)

# ---------- 1. VMMCALL sites (Q3 adjudication: is kernel HV-dependent?) ----------
hits, i = [], text.find(b"\x0f\x01\xd9")
while i != -1:
    hits.append(i); i = text.find(b"\x0f\x01\xd9", i + 1)
print(f"\n[1] VMMCALL (0F 01 D9) sites in kernel text: {len(hits)}")
for h in hits[:12]:
    print(f"    va=0x{TEXT_BASE + h:016x}")
findings["vmmcall_count"] = len(hits)
findings["vmmcall_va_first12"] = [f"0x{TEXT_BASE+h:x}" for h in hits[:12]]

# disassemble a few for context
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    print("    --- context, first 6 sites ---")
    for h in hits[:6]:
        n_ctx = 0
        for ins in md.disasm(text[h:h + 40], TEXT_BASE + h):
            print(f"      0x{ins.address:x}  {ins.mnemonic} {ins.op_str}")
            n_ctx += 1
            if n_ctx >= 5: break
        print("      ...")
except Exception as e:
    print("    (capstone unavailable:", e, ")")

# ---------- 2. MSR immediates: mov ecx, imm32 (AMD/custom range) ----------
msrs, msr_first = Counter(), {}
i = 0
while True:
    i = text.find(b"\xb9", i)
    if i == -1 or i + 5 > len(text): break
    imm = struct.unpack_from("<I", text, i + 1)[0]
    if 0xC0000000 <= imm <= 0xC001FFFF:
        msrs[imm] += 1
        msr_first.setdefault(imm, TEXT_BASE + i)
    i += 1
print(f"\n[2] mov ecx,<MSR> in AMD range: {len(msrs)} unique MSRs")
KNOWN = {0x00000174: "SYSENTER_CS", 0xC0000080: "EFER",
         0xC0000081: "STAR", 0xC0000082: "LSTAR", 0xC0000083: "CSTAR", 0xC0000084: "FMASK",
         0xC0000088: "FS_BASE?", 0xC0000089: "GS_BASE?", 0xC000008A: "KERNEL_GS_BASE?",
         0xC0000100: "FS_BASE", 0xC0000101: "GS_BASE", 0xC0000102: "KERNEL_GS_BASE",
         0xC0000103: "AMD_TSC_AUX",
         0xC000001F: "AMD_HWCR?", 0xC0000020: "AMD_NB_CFG?", 0xC0000021: "AMD_NB?",
         0xC0000039: "AMD_SPEC_CTRL?", 0xC000003E: "AMD_LS_CFG?",
         0xC0000041: "AMD_IC_CFG?", 0xC0000042: "AMD_DC_CFG?", 0xC0000043: "AMD_BU_CFG?",
         0xC0000048: "AMD_VM_CR?", 0xC0000049: "AMD_IGNNE?",
         0xC000004A: "AMD_SMM_CTL?", 0xC000004B: "AMD_VM_HSAVE_PA?",
         0xC0000015: "AMD_SYSCFG?", 0xC0000028: "AMD?",
         0xC0010010: "AMD_MTRR?", 0xC0010015: "AMD_SYSCFG", 0xC0010016: "AMD_IORR_BASE0?",
         0xC0010019: "AMD_IORR_MASK?", 0xC001001A: "AMD_TOP_MEM", 0xC001001D: "AMD_TOP_MEM2",
         0xC0010020: "AMD_PERF?", 0xC0010021: "AMD_PERF?", 0xC0010029: "AMD?",
         0xC0010030: "AMD_OSVW?", 0xC0010033: "AMD?",
         0xC0010053: "AMD_SMM_ADDR?", 0xC0010054: "AMD_SMM_MASK?",
         0xC0010061: "AMD_DBG?", 0xC0010062: "AMD_DBG?",
         0xC0011000: "AMD_LS_CFG", 0xC0011001: "AMD_IC_CFG", 0xC0011002: "AMD_DC_CFG",
         0xC0011020: "AMD_CFG?", 0xC0011021: "AMD_CFG?", 0xC0011022: "AMD_CPUID?",
         0xC0011023: "AMD_CFG?", 0xC001102A: "AMD_BU_CFG2?", 0xC001102B: "AMD_BU_CFG3?",
         0xC0012000: "AMD_EE?", 0xC0012001: "AMD_EE?", 0xC0012002: "AMD_EE?"}
label = lambda v: KNOWN.get(v, "UNKNOWN/CUSTOM" if v >= 0xC0010000 else "amd-std")
for imm, cnt in sorted(msrs.items(), key=lambda kv: -kv[1]):
    print(f"    MSR 0x{imm:08X}  {label(imm):22s} x{cnt:3d}  first_va=0x{msr_first[imm]:x}")
findings["msrs"] = {f"0x{imm:08X}": cnt for imm, cnt in msrs.items()}
customs = {f"0x{imm:08X}": cnt for imm, cnt in msrs.items()
           if imm >= 0xC0010000 and imm not in KNOWN}
findings["custom_msrs"] = customs
print(f"    => possibly-custom (>=0xC0010000, unlabeled): {customs}")

for name, pat in [("rdmsr(0F32)", b"\x0f\x32"), ("wrmsr(0F30)", b"\x0f\x30"),
                  ("cpuid(0FA2)", b"\x0f\xa2"), ("invlpg-ish(0F01)", b"\x0f\x01")]:
    c, i = 0, text.find(pat)
    while i != -1:
        c += 1; i = text.find(pat, i + 1)
    print(f"    {name}: {c}")

# ---------- 3. string adjudication (Titania / ccp / baikal naming dispute) ----------
targets = ["pup_update", "encsrv", "ccp", "CCP", "titania", "Titania", "TITANIA",
           "baikal", "Baikal", "syscon", "SYSCON", "Syscon", "apcie", "pcib",
           "oberon", "Oberon", "prospero", "Prospero", "orbis", "Orbis",
           "hammer_time", "FreeBSD", "freebsd", "Sony", "SIE", "Sbl", "SBL",
           "AuthMgr", "authmgr", "hypervisor", "Hypervisor", "vmm", "VMM",
           "gnm", "agc", "AGC", "nvme", "ahci", "xhci", "uart", "UART",
           "gdrm", "dce", "DCE", "i2c", "psp", "PSP", "sp5", "SP5", "amdccp",
           "gdc", "gfx", "dmem", "kstuff"]
found = {}
for t in targets:
    tb = t.encode()
    for rname, region, base in [("text", text, TEXT_BASE), ("data", data, DATA_BASE)]:
        i = region.find(tb)
        if i != -1:
            found.setdefault(t, []).append((rname, base + i, region.count(tb)))
print(f"\n[3] target strings found: {len(found)}/{len(targets)}")
for t, locs in sorted(found.items()):
    for rname, va, cnt in locs:
        print(f"    {t!r:16s} in {rname:4s} x{cnt:5d}  first_va=0x{va:x}")
findings["strings_found"] = {t: [(r, f"0x{va:x}", c) for r, va, c in l] for t, l in found.items()}
print("    NOT FOUND:", ", ".join(t for t in targets if t not in found))

strs = re.findall(rb"[ -~]{8,}", data)
open("./ps5/dump13/data_strings.txt", "wb").write(b"\n".join(strs))
print(f"    [data strings >=8ch: {len(strs):,} -> data_strings.txt]")
juicy = [s for s in strs if any(k in s for k in (
    b"Sony", b"SIE", b"FreeBSD", b"orbis", b"Prospero", b"Titania", b"ccp",
    b"syscon", b"pup_", b"encsrv", b"Sbl", b"sbl", b"baikal", b"apcie", b"psp"))]
print(f"    juicy: {len(juicy)}; first 30:")
for s in juicy[:30]:
    print("      ", s[:110].decode(errors="replace"))

# ---------- 4. SYSINIT-shaped candidates (24B: u32 sub, u32 order, ptr->text, ptr) ----------
import numpy as np
def sysinit_scan(region, base, rname):
    arr = np.frombuffer(region, dtype="<u8")
    n = len(arr)
    if n < 3: return Counter()
    func = arr[1:n-2]
    m = (func >= TEXT_BASE) & (func < TEXT_BASE + TEXT_SIZE)
    idx = np.nonzero(m)[0]
    subs = Counter()
    for j in idx[:300000]:
        s_off = (j - 1) * 8
        if s_off < 0 or s_off + 24 > len(region): continue
        sub, order = struct.unpack_from("<II", region, s_off)
        if sub < 0x40000000 and order < 0x10000:
            subs[sub] += 1
    return subs

for rname, region, base in [("text", text, TEXT_BASE), ("data", data, DATA_BASE)]:
    subs = sysinit_scan(region, base, rname)
    tot = sum(subs.values())
    print(f"\n[4] SYSINIT-shaped candidates in {rname}: {tot}")
    for sub, cnt in sorted(subs.items(), key=lambda kv: -kv[1])[:12]:
        print(f"    SI_SUB? 0x{sub:08X}  x{cnt}")
    findings[f"sysinit_candidates_{rname}"] = tot

# ---------- 5. verify AI#2's claimed HV physical addresses ----------
print("\n[5] HV phys-addr claim check (AI#2: 0x062800000 std / 0x8E0800000 Pro):")
for val in [0x062800000, 0x8E0800000, 0x060000000, 0x080000000,
            0x40000000, 0x800000000, 0xE0000000, 0x1000000000]:
    b = struct.pack("<Q", val)
    c = data.count(b) + text.count(b)
    print(f"    u64 0x{val:X}: {c} occurrences")
    findings[f"u64_0x{val:X}_count"] = c

print(f"\n[6] unmapped data pages: 688 in page range [21328, 22016) "
      f"=> va 0x{DATA_BASE + 21328*4096:x} .. 0x{DATA_BASE + 22016*4096:x}")

json.dump(findings, open("./ps5/dump13/first_pass_findings.json", "w"), indent=1)
print("\nsaved -> first_pass_findings.json")
