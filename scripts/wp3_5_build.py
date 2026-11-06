#!/usr/bin/env python3
"""WP3-STEP 5 build: MSR/CFI/console neutralization patches.

Adds to the 49 original boot patches:
  * cfi_check_fail (0x9e83f8c0) -> immediate ret  (CFI failures become no-ops;
    the failed indirect call is still made by the caller's jmp-back)
  * null putc stubs 0x9e7df4a0/0x9e7df4b0 -> debugcon 0x402 putc
    (console output actually leaves the VM)
  * 'or dword [rdi+0x100],1' in exception stubs (2 sites) -> NOP
    (faults when curthread == NULL early in boot; CR2=0x100 cascade)
  * all wrmsr in stub region + all wrmsr w/ Sony MSR in ECX -> NOP  (#GP source)
  * all rdmsr in stub region -> xor eax,eax (0) [+ clean combo when pattern
    matches: rdmsr;shl rdx,0x20;or rax,rdx -> xor eax/xor edx/nops]
"""
import sys, struct, json, re
from collections import Counter
import capstone

ELF = "./download/ps5_kernel_1360_reconstructed.elf"
OUT = "./wp3_boot"
KBASE_VA   = 0xFFFFFFFF9E3F0000
KBASE_PHYS = 0x1E3F0000
T_VA, T_OFF, T_SZ = 0x9E3F0000, 0x1000, 0xCC0000
D_VA, D_OFF, D_SZ = 0x9F0B0000, 0xCC1000, 0x3174000
STUB_LO_VA, STUB_HI_VA = 0x9E642C00, 0x9E648200

blob = open(ELF, "rb").read()
def va2img(va):
    lo = va & 0xFFFFFFFF
    if 0x9E3F0000 <= lo < 0x9F0B0000: return lo - 0x9E3F0000
    if 0x9F0B0000 <= lo < 0xA2224000: return 0xCC0000 + (lo - 0x9F0B0000)
    raise ValueError(hex(va))
def img_bytes(va, n):
    o = va2img(va)
    return (blob[T_OFF+o:T_OFF+o+n] if o < 0xCC0000 else blob[D_OFF+(o-0xCC0000):D_OFF+(o-0xCC0000)+n])

raw = blob[T_OFF:T_OFF+T_SZ] + blob[D_OFF:D_OFF+D_SZ]
assert len(raw) == 0x3E34000
open(f"{OUT}/kernel_raw.bin", "wb").write(raw)
print(f"kernel_raw.bin: {len(raw)} bytes")

# ---- vmmcall sites (unchanged from step 3) ----
d = json.load(open("./download/ps5_wp1/wp1_1_hypercalls.json"))
sites = []
for w in d["wrappers"]:
    for line in w["disasm"].split("\n"):
        m = re.match(r"\s*(0x[0-9a-f]+)\s+([0-9a-f]+)\s+vmmcall", line)
        if m:
            s = int(m.group(1), 16)
            if s < 0x1000000000000000: s |= 0xF000000000000000
            sites.append(s)
sites = sorted(set(sites))

patches = []      # (img_offset, expected, new, label)
ranges = []       # (start_off, end_off) for overlap check
def add(va, expect, new, label):
    off = va2img(va)
    got = img_bytes(va, len(expect))
    assert got == expect, f"{label}: expected {expect.hex()} got {got.hex()} @0x{va:x}"
    for s, e, lbl in ranges:
        assert not (off < e and s < off + len(new)), f"overlap: {label} vs {lbl}"
    ranges.append((off, off + len(new), label))
    patches.append((off, expect, new, label))

for s in sites:
    add(s, bytes.fromhex("0f01d9"), bytes.fromhex("31c090"), f"vmmcall@{s:#x}")
add(0x9FE4C15A, bytes([0x20]), bytes([0x00]), "console-unmute")
add(0x9ECCC006, bytes.fromhex("7431"), bytes.fromhex("9090"), "pmap-gateA-nop")
add(0x9ECCC014, bytes.fromhex("7423"), bytes.fromhex("9090"), "pmap-gateB-nop")
for va, old, new, label in [
    (0x9ECCC016 + 6, struct.pack("<I", 0x100), struct.pack("<I", 0x18C), "recursive-slot=0x18c"),
    (0x9ECCC020 + 6, struct.pack("<I", 0x1FE), struct.pack("<I", 0x11C), "d39=0x11c"),
    (0x9ECCC02A + 6, struct.pack("<I", 0),     struct.pack("<I", 0x1DC), "d30=0x1dc"),
]:
    add(va, old, new, label)
orig_putc = img_bytes(0x9E739BC0, 0x24)
new_putc = bytes.fromhex("4088f066ba0204eec3") + b"\x90" * (0x24 - 9)
add(0x9E739BC0, orig_putc, new_putc, "putc->debugcon")
add(0xA05E9598, bytes([0x20]), bytes([0x00]), "mute-data=0")
add(0x9E6AB4B5, bytes.fromhex("7869"), bytes.fromhex("eb69"), "psp-mbox-ready-force")
add(0x9E6AB5D3, bytes.fromhex("7477"), bytes.fromhex("eb77"), "psp-mbox-done-force")
add(0x9E6AB529, bytes.fromhex("758c"), bytes.fromhex("9090"), "psp-mbox-ready2-nop")
LIVE_RESIDUE_ZERO = [
    (0xA199B098, "vm_resv/vmem ptr"), (0xA191B538, "static-env-present flag"),
    (0xA191B560, "kern_envp array ptr"), (0xA1926628, "conslog-enabled gate"),
    (0x9FEB8930, "log()-enabled gate"),
    # WP4: UART-driver live residue -> the stuck spin-lock (softc at DMAP
    # 0xffff8e7701906c38 pointed into initrd-staging garbage -> infinite spin)
    (0xA184F370, "UART softc ptr (STUCK SPIN MUTEX)"),
    (0xA184F378, "UART softc ptr 2"),
    (0xA184F300, "UART stale DMAP ptr"),
]

# WP4b: console memory-profile descriptors (PPR16/PPR32/Cronos/Cronos32) request
# 12.71GB of "application memory" — impossible in a 1GB VM -> panic
# "Failed to allocate application memory". Shrink size(+0x10) and reserve(+0x18).
APP_MEM_SIZE  = 0x10000000   # 256 MB
APP_MEM_RESERVE = 0x4000000  # 64 MB
PROFILE_DESCRS = [
    (0x9F280D30, "PPR16"), (0x9F280D90, "PPR32"),
    (0x9F280DF0, "Cronos"), (0x9F280E50, "Cronos32"),
    (0xA1D0BA80, "live-residue copy"),
]
APP_MEM_ALIGN = 0x200000     # 2 MB (was 16GB/32GB console alignment!)
for base, nm in PROFILE_DESCRS:
    cur_align = struct.unpack("<Q", img_bytes(base + 0x08, 8))[0]
    if cur_align in (0x400000000, 0x800000000):
        add(base + 0x08, struct.pack("<Q", cur_align), struct.pack("<Q", APP_MEM_ALIGN), f"profile {nm} align->2M")
for base, nm in PROFILE_DESCRS:
    cur_size = struct.unpack("<Q", img_bytes(base + 0x10, 8))[0]
    cur_res  = struct.unpack("<Q", img_bytes(base + 0x18, 8))[0]
    if cur_size == 0x32D600000:
        add(base + 0x10, struct.pack("<Q", cur_size), struct.pack("<Q", APP_MEM_SIZE), f"profile {nm} appmem 12.7G->256M")
    if cur_res in (0x2B000000, 0x2C800000):
        add(base + 0x18, struct.pack("<Q", cur_res), struct.pack("<Q", APP_MEM_RESERVE), f"profile {nm} reserve->64M")
for va, label in LIVE_RESIDUE_ZERO:
    cur = img_bytes(va, 8)
    add(va, cur, bytes(8), label + " := 0")
print(f"base patches: {len(patches)}")

# ================= NEW WP4 PATCHES =================
print("\n-- WP4 neutralization patches --")

# 1. cfi_check_fail -> ret
add(0x9E83F8C0,
    bytes.fromhex("554889e54157 4156 5350 4889f3 4989fe".replace(" ", "")),
    bytes.fromhex("c3") + b"\x90" * 15,
    "cfi_check_fail->ret (CFI disabled)")

# 2. null putc stubs -> debugcon putc   putc(rdi=dev, esi=char)
dbg_putc = bytes.fromhex("4088f066ba0204eec3") + b"\x90" * 7   # 16 bytes
for va in (0x9E7DF4A0, 0x9E7DF4B0):
    add(va, bytes.fromhex("554889e55dc3") + b"\x90" * 10, dbg_putc,
        f"null-putc-stub@{va:#x}->debugcon")

# 3. stub 'or dword [rdi+0x100],1' (curthread==NULL fault) -> NOP
for va in (0x9E64482C, 0x9E644BB9):
    add(va, bytes.fromhex("838f 00010000 01".replace(" ", "")), b"\x90" * 7,
        f"stub-or[gs:0x20+0x100]@{va:#x}->nop")

# ================= WP5: NULL-curthread IVT read (phys-0!) =================
# Console path 0x9e7dea7d: mov gs:0x20,rax (curthread) — NULL in the window
# between machine_init's pcpu bzero/GS_BASE switch and thread0 install.
# mov 0x108(%rax),%rax  =>  VA 0+0x108 = phys 0x108 = BIOS IVT[0x42]+[0x43]
# = 0xc0007240f000ff53 (F000:FF53 default handler + C000:7240 VGA hook),
# stored as a fn-ptr at [r14+0xe8] and later CALLED -> non-canonical #GP ->
# "kernel trap 9 with interrupts disabled" spam loop.
# Fix: force rax=0 so the code's own NULL-check takes its designed fallback
# (je 0x9e7de181 -> call 0x9e7deb00(r14, NULL)). NB: 0xa1d0c310 is the stack
# canary — deliberately NOT patched (must stay consistent entry-vs-exit).
add(0x9E7DEA86,
    bytes.fromhex("488b8008010000"),            # mov 0x108(%rax),%rax
    bytes.fromhex("31c09090909090"),            # xor eax,eax; nop*5
    "curthread-NULL IVT read @0x9e7dea86 -> rax=0 (designed fallback)")

# ================= WP5b: PT-window translation path-B =================
# pmap fn 0x9eccc400: translates a region-table entry (DMAP VA) to its
# PT-window phys: out = (offset/48)*0x2000 + 0x22230000 — the imul magic
# r13=(2^64+2)/3<<12 implements /48 (multiples of 3 only).
# Path A (in-extent, 35 entries) works. Our boot's entry #38 lands 3 entries
# past the extent -> path B (0x9eccc562) whose bases +0x30/+0x48 are
# NEVER-INITIALIZED (dead on real HW; +0x30 also gets zeroed at runtime) ->
# ((r14-0)>>4)*magic = 0xaa84d260b7126000 non-canonical -> #GP @0x9eccc6e3.
# Fix: make path B use path A's live inputs —
#   sub 0x30(%rdx),%rsi -> sub %rdi,%rsi  (rdi = runtime region base)
#   add 0x48(%rdx),%rsi -> add 0x40(%rdx),%rsi (+0x40 = 0x22230000, stable)
# => path B computes the identical (correct) mapping for ANY entry index.
add(0x9ECCC565,
    bytes.fromhex("482b7230"),                    # sub 0x30(%rdx),%rsi
    bytes.fromhex("4829fe90"),                    # sub %rdi,%rsi; nop  (ModRM 0xFE!)
    "ptwin pathB base: [entry+0x30] -> rdi")
add(0x9ECCC571,
    bytes.fromhex("48037248"),                    # add 0x48(%rdx),%rsi
    bytes.fromhex("48037240"),                    # add 0x40(%rdx),%rsi
    "ptwin pathB window: [entry+0x48] -> [entry+0x40]")

# ---- WP5c: the OTHER 9 path-B translate twins in the pmap fn ----
# Same family, same struct: 'sub 0x30(%reg)' (uninit base) / 'add 0x48(%reg)'
# (uninit window). One-byte disp8 fix each: 0x30->0x28 (runtime region base),
# 0x48->0x40 (window base 0x22230000, runtime-stable).
PTWIN_B_SITES = [
    (0x9ECCC320, 0x9ECCC32C), (0x9ECCC399, 0x9ECCC3A5),
    (0x9ECCC418, 0x9ECCC424), (0x9ECCC46F, 0x9ECCC47B),
    (0x9ECCC5D5, 0x9ECCC5E1), (0x9ECCC643, 0x9ECCC64F),
    (0x9ECCC87B, 0x9ECCC887), (0x9ECCCA87, 0x9ECCCA93),
    (0x9ECCCAFE, 0x9ECCCB0A),
]
for sub_va, add_va in PTWIN_B_SITES:
    sb, ab = img_bytes(sub_va, 4), img_bytes(add_va, 4)
    assert sb[:2] == b"\x48\x2b" and sb[3] == 0x30, hex(sub_va)
    assert ab[:2] == b"\x48\x03" and ab[3] == 0x48, hex(add_va)
    add(sub_va + 3, bytes([0x30]), bytes([0x28]),
        f"ptwin-B sub@{sub_va:#x}: disp8 0x30->0x28 (region base)")
    add(add_va + 3, bytes([0x48]), bytes([0x40]),
        f"ptwin-B add@{add_va:#x}: disp8 0x48->0x40 (window base)")

# ---- WP5e: robust layout-independent path-B translate scan ----
# DISABLED 2026-10-28: the byte-pattern scan produced 32 extra sites in
# 0x9eccf035..0x9ecd7753 which are NOT all path-B translate twins — at least
# one false positive (fn containing 0x9ecd5449/0x9ecd54ab, RIP 0x9ecd58f9
# observed live in the tunable/pmap path) broke a legit +0x30/+0x48 field
# read -> pathological slow boot (hint-walk + fault storm crawl).
# The 10 KNOWN sites above stay (verified in GDB).
RUN_WP5E_SCAN = False
# Family: sub 0x30(%base),%r  [anything: movabs magic etc.]  shr $4  imul magic
#         add 0x48(%base),%r   — the +0x30/+0x48 fields are NEVER initialized.
# Forms:  A: 4x 2b M 30        B: 2b M 30 (32-bit)     C: 48 8b M 30 + 48 29 r
text_img = raw[:T_SZ]
KNOWN_SUB = {0x9ECCC320, 0x9ECCC399, 0x9ECCC418, 0x9ECCC46F, 0x9ECCC565,
             0x9ECCC5D5, 0x9ECCC643, 0x9ECCC87B, 0x9ECCCA87, 0x9ECCCAFE}
def _rm_ok(m):
    return 0x40 <= m <= 0x7F and (m & 7) != 4
n_5e = 0
i = 0
while i < T_SZ - 48:
    t = text_img
    sub_disp = None; sub_len = 0; base = None
    if t[i] in (0x48, 0x49, 0x4C, 0x4D) and t[i+1] == 0x2B and t[i+3] == 0x30 and _rm_ok(t[i+2]):
        sub_disp, sub_len, base = i + 3, 4, t[i+2] & 7           # form A
    elif (i > 0 and t[i] == 0x2B and t[i+2] == 0x30 and _rm_ok(t[i+1])
          and not (0x40 <= t[i-1] <= 0x4F)):
        sub_disp, sub_len, base = i + 2, 3, t[i+1] & 7           # form B (32-bit)
    elif (t[i] == 0x48 and t[i+1] == 0x8B and t[i+3] == 0x30 and _rm_ok(t[i+2])
          and t[i+4] == 0x48 and t[i+5] == 0x29
          and ((t[i+2] >> 3) & 7) == ((t[i+6] >> 3) & 7)):
        sub_disp, sub_len, base = i + 3, 4, t[i+2] & 7           # form C (load+sub)
    if sub_disp is not None and (T_VA + i) not in KNOWN_SUB:
        # forward: find add 0x48(%base),%r within 40 bytes, shr$4 + imul in between
        j = i + sub_len
        add_disp = None
        while j < i + 40:
            if (t[j] in (0x48, 0x49, 0x4C, 0x4D) and t[j+1] == 0x03 and t[j+3] == 0x48
                    and _rm_ok(t[j+2]) and (t[j+2] & 7) == base):
                seg = bytes(t[i+sub_len:j])
                has_shr = any(seg[k] in (0x48, 0x49, 0x4C, 0x4D) and seg[k+1] == 0xC1
                              and 0xE8 <= seg[k+2] <= 0xEF and seg[k+3] == 0x04
                              for k in range(len(seg) - 3))
                has_imul = any(seg[k] == 0x0F and seg[k+1] == 0xAF
                               for k in range(len(seg) - 1))
                if has_shr and has_imul:
                    add_disp = j + 3
                    break
            j += 1
        if add_disp is not None and RUN_WP5E_SCAN:
            add(T_VA + sub_disp, bytes([0x30]), bytes([0x28]),
                f"ptwin-5e sub@{T_VA+i:#x}: disp8 0x30->0x28")
            add(T_VA + add_disp, bytes([0x48]), bytes([0x40]),
                f"ptwin-5e add@{T_VA+add_disp-3:#x}: disp8 0x48->0x40")
            n_5e += 1
    i += 1
print(f"WP5e robust translate scan: {n_5e} extra sites patched")

# ================= WP5f: app-memory carve 4GB floor =================
# 0x9edfe277: movabs $0x100000000,%rdx — the app-memory carve base. On real
# PS5 the 4 profiles (256MB each after WP4 shrink) carve [4GB, 5GB). In a
# small VM nothing exists above 4GB -> carve returns NULL -> panic("Failed
# to allocate application memory", code 0x44). Rebase the floor to 1GB and
# run QEMU with -m 2G: profiles carve exactly [1GB, 2GB).
add(0x9EDFE279,
    struct.pack("<Q", 0x100000000),
    struct.pack("<Q", 0x40000000),
    "appmem carve floor: 4GB -> 1GB (needs -m 2G)")

# ================= WP5h: SMP residue gate =================
# [0xa20fe870] = 1 in the live dump ("SMP started, 8 CPUs"). Cold state = 0:
# with the gate set, stop_cpus() waits 100M pause-iterations for nonexistent
# APs to ack -> "timeout stopping cpus" -> nested panic
# "smp_targeted_tlb_shootdown: interrupts disabled". Gate := 0 makes all SMP
# paths take the single-CPU fast path (local invalidate, instant stop).
add(0xA20FE870, struct.pack("<Q", 1), struct.pack("<Q", 0),
    "smp_started gate := 0 (cold single-CPU state)")

# ================= WP6: unlock ALL printf -> console =================
# putchar (0x9e89d890) entry: `cmp dword [0xa197818c],0; je normal-path`
# — the retail console-direct gate. Gate==0 (retail): only panic/trap text
# (flags bit 0x20) ever reaches cnputc; normal boot printf is silent.
# Gate!=0 (devkit): every non-NUL char tail-jumps straight to cnputc.
# NOP the je so putchar ALWAYS takes the direct branch:
#   char==0 -> clean ret (0x9e89d918); else -> epilogue + jmp cnputc
#   (0x9ef0d260) -> consdev putc -> our debugcon 0x402 stub -> serial.log.
# The global itself stays 0 (18 other readers unaffected).
add(0x9E89D8A1,
    bytes.fromhex("7413"),
    bytes.fromhex("9090"),
    "putchar direct-console: je->nops (ALL printf -> cnputc -> debugcon)")

# ================= WP6b: ManuMode powerdown bypass =================
# Console module (0x9e7debb7 / 0x9e7df2c8) calls shutdown-check
# 0x9ebe0ce0(rbx): A = state[0x9fcd446c]==4 (RUNNING). Cold state=1 in our
# VM (no Titania/PSP to advance it) -> A fails -> "DBG: Power down on
# ManuMode..." -> ACPI S5 / recursive "double fault" 1s-poll deadlock.
# NB: do NOT force the state to 4 or bypass checker 0x9eef7920 itself:
# 0x9edf6afa calls the same checker and, when true, calls the LOST
# padding-zone fn 0x9e412e40 (0xCC in our dump!) -> INT3 -> triple fault.
# The state must stay 1 (natural); only neuter THIS shutdown entry:
# patch 0x9ebe0ce0's first byte push rbp -> ret (identical to the
# all-checks-pass path, which just returns).
add(0x9EBE0CE0,
    bytes.fromhex("55"),
    bytes.fromhex("c3"),
    "console shutdown-check 0x9ebe0ce0 -> ret (ManuMode powerdown bypass)")

# ================= WP6e: lost-function stubs (live-dump padding zone) =======
# The reconstructed image is missing 2.43MB of .text ([0x9e3f0090,
# 0x9e64025f) = 0xCC). When the boot path reaches a call into that zone
# the CPU executes 0xCC -> INT3 -> (IDT still null) triple fault -> QEMU
# reset. First discovered: 0x9e412e40 (RUNNING-state transition handler,
# called from 0x9edf6b39 with (prop8003, prop8004)). Stub it to `ret`
# (feature-disabled semantics). Future INT3s at other lost fns: add here.
LOST_FN_STUBS = [
    (0x9E412E40, "running-state transition (lost in dump)"),
]
for va, why in LOST_FN_STUBS:
    add(va, bytes([0xCC]), bytes([0xC3]), f"lost-fn stub {why}: int3->ret")

# ---- WP6f: family scan — every translate computing a PT-window VA ----
# Pattern: shr r64,4 ; imul r64,magic ; add r64,[reg+0x48]  where the
# +0x48 window-base field is NEVER initialized (its initializer lives in
# the lost 0xCC zone). Fix: disp8 0x48 -> 0x40 (runtime window base).
# EXCEPTION: 0x9ece1bfa (the DMAP-PD fill, live-crash-confirmed) — the
# fallback there feeds the FULL DMAP VA into the /48 magic because our
# allocations exceed the live-residue entry coverage -> astronomical
# non-canonical r11. The caller already computed the correct window slot
# in rdi; replace the whole add with `mov r11, rdi` (+nop).
add(0x9ECE1BFA,
    bytes.fromhex("4c035b48"),              # add r11, [rbx+0x48]
    bytes.fromhex("4c89fb90"),              # mov r11, rdi ; nop
    "DMAP-PD fill: garbage translate -> use caller's window slot (rdi)")
WP6F_SPECIAL = {0x9ECE1BFA}
# entry0 (+0x30) must hold the region DMAP base so the fallback translate
# subtracts it instead of 0 (raw DMAP VA -> non-canonical garbage).
add(0xA1F37EC0, struct.pack("<Q", 0), struct.pack("<Q", 0xFFFF8E7722253000),
    "win-entry0 +0x30 := region DMAP base (fallback input fix)")
text_img = raw[:T_SZ]
n_6f = 0
i = 0
while i < T_SZ - 64:
    t = text_img
    # shr r64, 4 : REX.W (48: rax-rdi) or REX.WB (49: r8-r15) c1 e? 04
    if t[i] in (0x48, 0x49) and t[i+1] == 0xC1 and 0xE8 <= t[i+2] <= 0xEF and t[i+3] == 0x04:
        # find imul r64,r64 within 20 bytes
        j = i + 4
        imul_at = None
        while j < i + 24:
            if t[j] in (0x4C, 0x4D, 0x49, 0x48) and t[j+1] == 0x0F and t[j+2] == 0xAF:
                imul_at = j
                break
            j += 1
        if imul_at is not None:
            # find add r64, [reg+0x48] within 24 bytes after imul
            k = imul_at + 3
            while k < imul_at + 28:
                if t[k] in (0x4C, 0x4D, 0x49, 0x48) and t[k+1] == 0x03 and t[k+3] == 0x48 \
                   and 0x40 <= t[k+2] <= 0x7F and (t[k+2] & 7) != 4:
                    if (T_VA + k) not in WP6F_SPECIAL:
                        try:
                            add(T_VA + k + 3, bytes([0x48]), bytes([0x40]),
                                f"ptwin-6f add@{T_VA+k:#x}: disp8 0x48->0x40 (window base)")
                            n_6f += 1
                        except AssertionError:
                            pass  # already covered by an earlier patch (ptwin-B etc.)
                    break
                k += 1
    i += 1
print(f"WP6f window-translate family scan: {n_6f} sites patched")

# ---- WP6g: the sub-side of the translate family ----
# sub r64, [entry+0x30] ; (shr 4 ; imul magic) — the +0x30 field is
# rewritten to 0 at runtime by the entry-registration code; the raw DMAP
# VA then feeds the /48 magic -> non-canonical -> #GP. Redirect every
# such sub to +0x28 (the runtime-valid region DMAP base).
n_6g = 0
i = 0
while i < T_SZ - 64:
    t = text_img
    if t[i] in (0x48, 0x49, 0x4C, 0x4D) and t[i+1] == 0x2B and t[i+3] == 0x30 \
       and 0x40 <= t[i+2] <= 0x7F and (t[i+2] & 7) != 4:
        # require shr r64,4 within 32 bytes ahead and imul within 24 after that
        j = i + 4
        shr_at = None
        while j < i + 36:
            if t[j] in (0x48, 0x49) and t[j+1] == 0xC1 and 0xE8 <= t[j+2] <= 0xEF and t[j+3] == 0x04:
                shr_at = j
                break
            j += 1
        if shr_at is not None:
            k = shr_at + 4
            ok = False
            while k < shr_at + 28:
                if t[k] in (0x4C, 0x4D, 0x49, 0x48) and t[k+1] == 0x0F and t[k+2] == 0xAF:
                    ok = True
                    break
                k += 1
            if ok:
                try:
                    add(T_VA + i + 3, bytes([0x30]), bytes([0x28]),
                        f"ptwin-6g sub@{T_VA+i:#x}: disp8 0x30->0x28 (region DMAP base)")
                    n_6g += 1
                except AssertionError:
                    pass  # already covered
    i += 1
print(f"WP6g sub-family scan: {n_6g} sites patched")

# 4/5. wrmsr + rdmsr neutralization
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
stub_off_lo = STUB_LO_VA - T_VA
stub_off_hi = STUB_HI_VA - T_VA
stub_code = raw[stub_off_lo:stub_off_hi]
rdmsr_addrs, wrmsr_addrs = [], []
for ins in md.disasm(stub_code, STUB_LO_VA):
    if ins.mnemonic == "rdmsr": rdmsr_addrs.append(ins.address)
    elif ins.mnemonic == "wrmsr": wrmsr_addrs.append(ins.address)
print(f"stub region rdmsr: {len(rdmsr_addrs)}, wrmsr: {len(wrmsmsr) if False else len(wrmsr_addrs)}")

SONY = {0x1DD, 0x1DE, 0x1D9, 0xC0000110, 0xC0000111, 0xC0000112, 0xC0000113,
        0xC0000114, 0xC0000115, 0xC0000116, 0xC0000117, 0xC0000118, 0xC0000120}
text_img = raw[:T_SZ]
wr_all = [m.start() for m in re.finditer(rb"\x0f\x30", text_img)]
sony_wr = set()
for h in wr_all:
    win = text_img[max(0, h-24):h]
    for m in re.finditer(rb"\xb9(....)", win, re.S):
        if struct.unpack("<I", m.group(1))[0] in SONY:
            sony_wr.add(T_VA + h)
            break
# also movabs rcx, imm64 (48 b9 ....) pattern
for h in wr_all:
    win = text_img[max(0, h-24):h]
    for m in re.finditer(rb"\x48\xb9(........)", win, re.S):
        if struct.unpack("<Q", m.group(1))[0] in SONY:
            sony_wr.add(T_VA + h)
            break
print(f"sony-ECX wrmsr sites anywhere: {len(sony_wr)}")
must_have = 0x9EDF959B
print(f"  user site 0x9edf959b present: {must_have in sony_wr}")
for a in sorted(sony_wr):
    print(f"    {a:#x}")

# wrmsr patch set = stub-region ones + sony-ECX ones
for va in sorted(set(wrmsr_addrs) | sony_wr):
    add(va, bytes.fromhex("0f30"), bytes.fromhex("9090"), f"wrmsr@{va:#x}->nop")

# rdmsr: clean combo when followed by 'shl rdx,0x20; or rax,rdx'
COMBO_TAIL = bytes.fromhex("48c1e220 4809d0".replace(" ", ""))
n_combo = n_plain = 0
for va in rdmsr_addrs:
    if img_bytes(va, 9)[:2] == b"\x0f\x32" and img_bytes(va + 2, 7) == COMBO_TAIL:
        add(va, bytes.fromhex("0f32") + COMBO_TAIL,
            bytes.fromhex("31c031d2") + b"\x90" * 5, f"rdmsr@{va:#x}->xor0")
        n_combo += 1
    else:
        add(va, bytes.fromhex("0f32"), bytes.fromhex("31c0"), f"rdmsr@{va:#x}->xor eax")
        n_plain += 1
print(f"rdmsr patches: combo={n_combo} plain={n_plain}")

print(f"\nTOTAL PATCHES: {len(patches)}")

# ---- emit patches.inc ----
with open(f"{OUT}/patches.inc", "w") as f:
    f.write("; auto-generated by wp3_5_build.py — DO NOT EDIT\n")
    f.write(f"PATCH_COUNT equ {len(patches)}\n")
    f.write("patch_table:\n")
    for off, expect, new, label in patches:
        f.write(f"    dd 0x{off:08x}          ; phys 0x{KBASE_PHYS+off:08x} — {label}\n")
        f.write(f"    dd {len(expect)}\n")
        f.write(f"    db {','.join(str(b) for b in expect)}\n")
        f.write(f"    db {','.join(str(b) for b in new)}\n")
print(f"patches.inc: {len(patches)} entries")

# ---- meta.inc + params.inc (identical regeneration) ----
def align8(n): return (n + 7) & ~7
meta = b""
def rec(t, data):
    global meta
    r = struct.pack("<II", t, len(data)) + data
    meta += r + b"\0" * (align8(len(r)) - len(r))
rec(1, b"kernel\0"); rec(2, b"elf kernel\0")
rec(3, struct.pack("<Q", len(raw)))
smap = b"".join(struct.pack("<QQI", b, l, t) for b, l, t in [
    (0x1000, 0x9B000 - 0x1000, 1), (0x9C000, 0xF0000 - 0x9C000, 1),
    (0x100000, 0x80000000 - 0x100000, 1)])
rec(0x9001, smap)
meta += struct.pack("<II", 0, 0)
assert len(meta) <= 0x1000
with open(f"{OUT}/meta.inc", "w") as f:
    f.write("; auto-generated preload metadata (modulep @0x22224000)\n")
    f.write(f"META_LEN equ {len(meta)}\nmeta_blob:\n")
    for i in range(0, len(meta), 16):
        f.write(f"    db {','.join(str(b) for b in meta[i:i+16])}\n")

pb = {}
def pb_bytes(phys, data): pb[phys] = data
pb_bytes(0x9B310, bytes.fromhex("c0151b185261"))
pb_bytes(0x9B318, b"\xff" * 6)
pb_bytes(0x9B350, bytes.fromhex(
    "0100000000000000010000000000000022010101000000000c00000000003600200444000000000001000000000000000001000c0c0c0c008d00010000000000"))
pb_bytes(0x9B6BE, b"\x00"); pb_bytes(0x9B6C0, struct.pack("<I", 0))
pb_bytes(0x9B6D4, struct.pack("<I", 0x00010000)); pb_bytes(0x9B6D8, struct.pack("<I", 0))
pb_bytes(0x9B6DC, b"\x00"); pb_bytes(0x9B6DD, b"\x00")
pb_bytes(0x9B6E0, struct.pack("<I", 0x00120101))
pb_bytes(0x9B6E4, struct.pack("<Q", 0)); pb_bytes(0x9B6EC, struct.pack("<Q", 0))
pb_bytes(0x9BF44, bytes.fromhex("660000")); pb_bytes(0x9BF48, struct.pack("<I", 1))
pb_bytes(0x9BF4C, struct.pack("<Q", 0))
pb_bytes(0x9BF54, struct.pack("<Q", 0x1E1E0000))
pb_bytes(0x9BF5C, b"\x00")
pb_bytes(0x9BF6C, struct.pack("<I", 0x00070000)); pb_bytes(0x9BF70, struct.pack("<I", 0x00030000))
pb_bytes(0x9BF74, struct.pack("<I", 0x7F9D0000)); pb_bytes(0x9BF78, struct.pack("<I", 0x00610000))
pb_bytes(0x9B6F4, struct.pack("<Q", 0))
with open(f"{OUT}/params.inc", "w") as f:
    f.write("; auto-generated phys param block\n")
    f.write(f"PARAM_COUNT equ {len(pb)}\nparam_table:\n")
    for phys in sorted(pb):
        data = pb[phys]
        f.write(f"    dd 0x{phys:08x}\n    dd {len(data)}\n")
        f.write(f"    db {','.join(str(b) for b in data)}\n")
print("meta.inc + params.inc written")
print("\nDONE — run: nasm -f elf32 -I wp3_boot/ -o wp3_boot/trampoline.o scripts/trampoline.asm && ld -m elf_i386 -T wp3_boot/tramp.ld -o wp3_boot/trampoline.elf wp3_boot/trampoline.o")
