#!/usr/bin/env python3
# Reproducible Patcher for PS5 13.60 Kernel Boot on QEMU
import base64, hashlib, sys, zlib

TARGET_MD5 = "520808c90b58241f454baeae0db0c8cc"
DIFF_DATA  = "eNqtV9tuEzEQ/ZW8IECq6Pg+AxIQCXF5QCABAikbUDbZQEUpVcslCNFvZxzvJpvsTCmIByeOz3jmzM12JjcSGLIHo/p6tWrg+s2DEa9YMnsrFGlnBV1yvqwsZzw8IzV/Lzo0xTV68vq5dbdH5z/Oj06Ovoy+z44/juafP50eN1+aO6PT2dnHo5P3t6qTagVFsQlgfKuZ5uMXT6oVEit2PJkbntSHPFsu+Zf7Wq2MHU9YcMFS7oJ/QsGAB4b8wQtosnYmSNP+QtnI0zk8ztt5wl4ATsZVNZ6O347fTbORjpVNdsBqLrM6K6qz1vp+JjXNxl8+vblndke/Bxh6Xctew7JngUfigcXJbjT0q1otljcuMxks/pvJRzlORazhuEHOPu9dxElzaWR3rMcQt9afXp7mznomWT/kkGJWHLKFYrphOhSF1K6zuZ/LhP6qudyYzo6wUZjzsG3gwRXrhuc0u7ywzJ77ZNb1dNX6M1wgf835QaE5g7xrvz6qVc0BnK3l/xQxY+LVS6Xfk9UqLbPvreHckf5nS37Tlq/6Cz0mWV+fhKX430jUpWW2JK71F/ZIdAS89Zuc9ddDEHL5RklkRBCVIKC4Ti4O1y1agvaMZfLvR9x9qbhPOdvQSoUEMXVSBatt7tQsu5aJABi7G6Au2qMPfODBdh+y3hwOWm73+ZAsbmTuMDUaCLjNtUH1UCCRM9RjB3x6zHxppT1PEkaIXdc2dFhVTGoohtwlUUpSBtCjCBjuLRnwycpABJCB5JIMoMLKpiizsoiyDe4CGXAQogwYq+ywTnbQOc1GQNkPl4yiCr2iSixsBnJ4ZcBpO4KXWQWr5DyI3ZYBUvIRgWTjUTMeieSQJI1VsoqNhEEDUFaFHEUFUIyT1gZklLCTkz0PoMRq87YTADlWIRepDGCUVWldG0z7KB0CSokGC4pxTqCyQ+na4EAuuOCUgguerAzw0Sx7znyNAiisgldYBS/XVYgg1xUDSj6ikU+GwAe1zIpfhgqQrAJosUpKUYfk0clA/zLfAZJigwtRZkVaosgoNsiIxWAQKXR/yWgxKW/f9hpFfn9YbO/Z/l0YXIyud73WTXVW/gB1Oxk220dE91S66K7VVsg7fg5shZbzDxfDizd678FupebUDKWMSdxrfnONP7t4tiFjbKTcvFsVszzsvRZF59ubvfWm/n53h+haBKH/aqm/9USmvwHHFRJx"

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "wp3_boot/kernel_raw.bin"
    if not os.path.exists(target):
        print(f"[!] Target binary not found: {target}")
        sys.exit(1)
    buf = bytearray(open(target, "rb").read())
    patches = eval(zlib.decompress(base64.b64decode(DIFF_DATA)))
    for off, chunk in patches:
        buf[off : off + len(chunk)] = chunk
    open(target, "wb").write(buf)
    md5 = hashlib.md5(buf).hexdigest()
    print(f"[+] Successfully applied patches -> MD5: {md5}")

if __name__ == "__main__":
    import os
    main()
