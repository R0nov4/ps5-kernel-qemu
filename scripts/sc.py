import math
import os
import struct
from collections import Counter

filename = "PS5UPDATE.pup"
filesize = os.path.getsize(filename)

with open(filename, "rb") as f:
    print("=" * 60)
    print("[1] PUP HEADER INSPECTION")
    print("=" * 60)

    # بررسی یک ناحیه احتمالی از هدر
    f.seek(1024)
    raw_hdr = f.read(16)

    print("Raw Header:", raw_hdr.hex(" "))

    # ساختار زیر صرفاً یک فرض برای آزمایش است؛
    # تا زمانی که فرمت هدر تأیید نشده، نتایج قطعی نیستند.
    if len(raw_hdr) >= 14:
        try:
            (
                magic,
                unk1,
                unk2,
                flags,
                reserved,
                hdr_size,
                meta_size,
                file_cnt,
            ) = struct.unpack("<IBBBBHHH", raw_hdr[:14])

            print(f"Magic          : 0x{magic:08X}")
            print(f"Unknown 1      : {unk1}")
            print(f"Unknown 2      : {unk2}")
            print(f"Flags          : 0x{flags:02X}")
            print(f"Reserved       : 0x{reserved:02X}")
            print(f"Header Size    : {hdr_size}")
            print(f"Metadata Size  : {meta_size}")
            print(f"File Count     : {file_cnt}")

        except struct.error as exc:
            print("Header parsing failed:", exc)

    print("\n" + "=" * 60)
    print("[2] FULL-FILE ENTROPY HEATMAP")
    print("=" * 60)

    step = max(filesize // 60, 1)
    heatmap = ""
    zones = []

    for i in range(60):
        offset = i * step

        if offset >= filesize:
            break

        f.seek(offset)
        chunk = f.read(65536)  # نمونه 64 کیلوبایتی

        if not chunk:
            break

        counts = Counter(chunk)
        length = len(chunk)

        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counts.values()
        )

        if entropy < 1.0:
            symbol = "░"
            category = "VERY LOW ENTROPY"
        elif entropy < 6.5:
            symbol = "▒"
            category = "LOW/MODERATE ENTROPY"
        elif entropy < 7.95:
            symbol = "▓"
            category = "HIGH ENTROPY"
        else:
            symbol = "█"
            category = "NEAR-UNIFORM DISTRIBUTION"

        heatmap += symbol
        zones.append((offset, entropy, category))

    print(f"File Size: {filesize / (1024 * 1024):.2f} MB")
    print(f"Map: [{heatmap}]")
    print(
        "Legend: "
        "░ = Very Low | "
        "▒ = Low/Moderate | "
        "▓ = High | "
        "█ = Near-Uniform"
    )

    print("\nSampled Regions:")
    for offset, entropy, category in zones:
        print(
            f"Offset 0x{offset:08X} "
            f"({offset / (1024 * 1024):.2f} MB) "
            f"-> Entropy: {entropy:.4f} [{category}]"
        )

    print("\n" + "=" * 60)
    print("[3] CHI-SQUARE DISTRIBUTION TEST")
    print("=" * 60)

    sample_offset = 50 * 1024 * 1024

    if filesize > sample_offset:
        f.seek(sample_offset)
        sample = f.read(1024 * 1024)

        if sample:
            counts = Counter(sample)
            expected = len(sample) / 256.0

            chi_sq = sum(
                ((counts[b] - expected) ** 2) / expected
                for b in range(256)
            )

            print(f"Sample Size     : {len(sample)} bytes")
            print(f"Sample Offset   : 0x{sample_offset:08X}")
            print(f"Chi-Square Score: {chi_sq:.2f}")

            if 200 <= chi_sq <= 310:
                print(
                    "Verdict: Byte distribution is "
                    "approximately uniform."
                )
            else:
                print(
                    "Verdict: Byte distribution differs "
                    "from the selected uniformity range."
                )

            print(
                "Note: This statistical test alone cannot "
                "identify AES encryption or prove that a "
                "hardware-protected key is being used."
            )
        else:
            print("Could not read the requested sample.")
    else:
        print("File is too small for the 50 MB sample offset.")
