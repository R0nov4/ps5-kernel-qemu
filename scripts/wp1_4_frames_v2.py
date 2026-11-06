#!/usr/bin/env python3
"""Frame scan v2 — CORRECT Sony extended trapframe layout:
  +0x00..0x70  15 GP regs (rdi,rsi,rdx,rcx,r8,r9,rax,rbx,rbp,r10,r11,r12,r13,r14,r15)
  +0x78        vector/trapno (dword)
  +0x7c/+0x7e  fs/gs (words)
  +0x80        err (qword)
  +0x88        frame flags (dword): bit0=1 set by stubs; bit3(8)=extended-MSRs-restore-needed
  +0x8c/+0x8e  es/ds (words)
  +0x90        MSR 0x1DD
  +0x98        MSR 0x1DE
  +0xa0..0xd8  MSRs 0xC0000110..0xC0000117
  +0xe0        (qword, stub writes 0)
  +0xe8        interrupted RIP   (CPU-pushed)
  +0xf0        interrupted CS    (CPU-pushed dword)
  +0xf8        interrupted RFLAGS
  (+0x100/0x108 RSP/SS if CPL change)
Validation: CS==0x20 (kernel) or CS&3==3 (user); RFLAGS sane; vector<0x100; fs/gs/es/ds small.
"""
import sys, struct
sys.path.insert(0, "./scripts")
import wp1_lib as L
import numpy as np
from collections import defaultdict, Counter

blob = L._blob
arr = np.frombuffer(blob, dtype="<u8")
n8 = len(arr)

USER_MAX = 0x0000800000000000  # plausible userland ceiling

kern_hits, user_hits = [], []
k = 0
while k + 32 < n8:
    vec_dw = int(arr[k + 15]) & 0xFFFFFFFF           # +0x78
    if vec_dw >= 0x100:
        k += 1
        continue
    flags_dw = int(arr[k + 17]) >> 32                 # +0x88 (high half of qword at +0x80... no)
    # careful: +0x88 is a dword; qword at k+17 covers +0x88..+0x8f (flags dword + es/ds words)
    q17 = int(arr[k + 17])
    flags_dw = q17 & 0xFFFFFFFF
    es, ds = (q17 >> 32) & 0xFFFF, (q17 >> 48) & 0xFFFF
    q14 = int(arr[k + 15])                            # +0x78: vector dword + fs/gs words
    fs, gs = (q14 >> 32) & 0xFFFF, (q14 >> 48) & 0xFFFF
    if flags_dw & ~0xF:
        k += 1
        continue
    if max(fs, gs, es, ds) >= 0x40:
        k += 1
        continue
    err = int(arr[k + 16])                            # +0x80 err
    rip = int(arr[k + 29])                            # +0xe8 interrupted RIP
    cs = int(arr[k + 30]) & 0xFFFFFFFF                # +0xf0 CS dword
    rfl = int(arr[k + 31])                            # +0xf8 RFLAGS
    if (rfl >> 32) != 0 or not (rfl & 2) or (rfl & 0xFF000000):
        k += 1
        continue
    is_kern = (cs == 0x20 or cs == 0x28) and L.in_text(rip)
    is_user = (cs & 3) == 3 and (0x1000 <= rip < USER_MAX)
    if not (is_kern or is_user):
        k += 1
        continue
    msrvals = [int(arr[k + 18 + j]) for j in range(10)]
    rec = (k * 8, vec_dw, flags_dw, rip, cs, rfl, err, msrvals)
    (kern_hits if is_kern else user_hits).append(rec)
    k += 1

print(f"kernel-side frames: {len(kern_hits)}   user-side frames: {len(user_hits)}")

def report(hits, label):
    print(f"\n=== {label} ===")
    # frames whose MSRs were actually RESTORED (flags bit3) are the interesting ones,
    # but ALL frames carry the MSR snapshot
    byset = defaultdict(list)
    for off, vec, fl, rip, cs, rfl, err, vals in hits:
        byset[tuple(vals)].append((off, vec, fl, rip, cs))
    print(f"distinct 10-MSR sets: {len(byset)}")
    for key, lst in sorted(byset.items(), key=lambda kv: -len(kv[1]))[:20]:
        offs = ", ".join(f"0x{o:x}(v{v:#x},f{f})" for o, v, f, _, _ in lst[:3])
        print(f"\n  x{len(lst)}  @{offs}")
        print(f"      0x1DD = {key[0]:#018x}   0x1DE = {key[1]:#018x}")
        for j in range(8):
            print(f"      0xC000011{j} = {key[2+j]:#018x}")

report(kern_hits, "KERNEL-INTERRUPT FRAMES (CS=0x20)")
if user_hits:
    report(user_hits, "USER-ENTRY FRAMES (CS&3==3)")
