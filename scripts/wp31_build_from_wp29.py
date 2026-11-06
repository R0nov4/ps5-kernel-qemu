#!/usr/bin/env python3
# ============================================================================
# wp31_build_from_wp29.py — one-shot WP29 -> WP31 kernel image builder
#
# USAGE (on your laptop, inside the extracted ps5_boot_kit directory):
#     python3 scripts/wp31_build_from_wp29.py
#   or with explicit paths:
#     python3 scripts/wp31_build_from_wp29.py <wp29_kernel_raw.bin> <out.bin>
#
# INPUT : the verified WP29 image  (md5 e9cccbeb03f468c4708d53361fbde1f6)
#         default path: wp3_boot/kernel_raw.bin  (a .wp29.bak backup is made)
# OUTPUT: the WP31 image         (md5 c85632c931c85b4ec2ae1db1a2ba3374)
#
# PATCHES (all byte-verified against the WP29 image, idempotent):
#  G52  [A] 9B @0x9e983cd4 : mov rax,[rip];jmp -> test rax,rax; jz 0x9e983d16
#            (NULL zone-alloc result skips the ip_id/arc4rand seeding loop)
#       [B] 8B @0xa1a74050 : residue 0xffffff80083fc000 -> 0 (defuse free)
#  G53      the post-ipfw2 crash: bcopy(src=NULL, dst, 0x2000) at 0x9e649c20
#            (rep movsq, READ fault VA 0). src = source manager's table
#            ENTRIES array — NULL because its 0x2000-byte alloc failed
#            (arena exhaustion). Fix = NULL-guard stub in dead padding:
#            cave 0x9e86bb23:  test rdi,rdi ; jz ret ; call bcopy ; ret
#            redirects: 0x9e86b933 (crash frame, zero-frame fn) and
#            0x9e86b76a (sibling site in 0x9e86b680)
#  G54      8B @0xa0cbbab8 : timecounter LIST head residue 0xa0fec680 -> 0
#            (TSC-low self-cycle at sysinit #1328: insert-head would set
#            TSC-low->next = TSC-low. active tc @0xa0cbb8b0 untouched.)
#
# Chain (verified): WP29 --G52--> WP30 (706ec1ee...) --G53+G54--> WP31
# ============================================================================
import hashlib, struct, os, shutil, sys

MD5_WP29 = 'e9cccbeb03f468c4708d53361fbde1f6'
MD5_WP30 = '706ec1eeb50ae46ee0e47a0c4d11c8ea'
MD5_WP31 = 'c85632c931c85b4ec2ae1db1a2ba3374'
KTEXT = 0xFFFFFFFF9E3F0000
BCOPY = 0xFFFFFFFF9E649BE0
CAVE  = 0xFFFFFFFF9E86BB23

def off(va):
    return va - KTEXT

def patch(img, va, expect, new, name):
    o = off(va)
    cur = bytes(img[o:o + len(expect)])
    if cur == new:
        print(f"  [skip] {name} @ {va:#x} (already patched)")
        return True
    if cur != expect:
        print(f"  [FAIL] {name} @ {va:#x}: expected {expect.hex()}, found {cur.hex()}")
        print("  The input image is NOT the expected WP29 base — aborting (nothing written).")
        return False
    img[o:o + len(new)] = new
    print(f"  [ ok ] {name} @ {va:#x}: {expect.hex()} -> {new.hex()}")
    return True

def main():
    if len(sys.argv) >= 3:
        src, dst = sys.argv[1], sys.argv[2]
    else:
        src = dst = os.path.join('wp3_boot', 'kernel_raw.bin')
    if not os.path.isfile(src):
        print(f"input not found: {src}")
        return 1

    img = bytearray(open(src, 'rb').read())
    m = hashlib.md5(img).hexdigest()
    print(f"[*] input  : {src}  ({len(img)} bytes)")
    print(f"    md5    : {m}")
    if m == MD5_WP31:
        print("[*] already the WP31 image — nothing to do.")
        return 0
    if m != MD5_WP29:
        print(f"[!] md5 mismatch — expected WP29 base {MD5_WP29}")
        return 1

    print("[*] applying G52 (the WP30 patch set)...")
    if not patch(img, 0xFFFFFFFF9E983CD4,
                 bytes.fromhex('488b050dac7703eb0d'),
                 bytes.fromhex('4885c00f8439000000'),
                 "G52[A] NULL-alloc guard (test rax,rax; jz 0x9e983d16)"):
        return 1
    if not patch(img, 0xFFFFFFFFA1A74050,
                 bytes.fromhex('00c03f0880ffffff'),
                 bytes.fromhex('0000000000000000'),
                 "G52[B] residue free() defuse"):
        return 1
    m = hashlib.md5(img).hexdigest()
    print(f"[*] after G52: md5 {m}  (WP30: {MD5_WP30})")
    if m != MD5_WP30:
        print("[!] G52 reconstruction mismatch — aborting.")
        return 1

    print("[*] applying G53 (NULL-entries table guard)...")
    stub = bytes.fromhex('4885ff7405e8') + struct.pack('<i', BCOPY - (CAVE + 10)) + bytes.fromhex('c3')
    if not patch(img, CAVE, b'\x90' * 13, stub,
                 "G53[cave] guard stub (test rdi,rdi; jz ret; call bcopy; ret)"):
        return 1
    if not patch(img, 0xFFFFFFFF9E86B933,
                 bytes.fromhex('e8a8e2ddff'),
                 b'\xe8' + struct.pack('<i', CAVE - (0xFFFFFFFF9E86B933 + 5)),
                 "G53[A] crash-site call redirect (zero-frame fn 0x9e86b910)"):
        return 1
    if not patch(img, 0xFFFFFFFF9E86B76A,
                 bytes.fromhex('e871e4ddff'),
                 b'\xe8' + struct.pack('<i', CAVE - (0xFFFFFFFF9E86B76A + 5)),
                 "G53[B] sibling-site call redirect (fn 0x9e86b680)"):
        return 1

    print("[*] applying G54 (TSC-low list-head zero)...")
    if not patch(img, 0xFFFFFFFFA0CBBAB8,
                 bytes.fromhex('80c6fea0ffffffff'),
                 bytes.fromhex('0000000000000000'),
                 "G54 timecounter list head <- 0"):
        return 1

    m = hashlib.md5(img).hexdigest()
    if m != MD5_WP31:
        print(f"[!] final md5 {m} != expected {MD5_WP31} — aborting.")
        return 1

    if os.path.abspath(src) == os.path.abspath(dst):
        bak = src + '.wp29.bak'
        if not os.path.exists(bak):
            shutil.copy2(src, bak)
            print(f"[*] backup : {bak}")
    open(dst, 'wb').write(img)
    print(f"\n[+] WP31 image written: {dst}")
    print(f"    md5 {m}  ({len(img)} bytes)")
    print("[*] next: bash run.sh 240   -> expected: past ipfw2, past the")
    print("    table-clone NULL, past TSC-low registration; next frontier TBD.")
    return 0

if __name__ == '__main__':
    sys.exit(main())
