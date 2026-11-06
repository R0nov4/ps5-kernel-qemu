#!/usr/bin/env bash
set -e

# Base directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GZ_NAME="kernel-13.60-live.bin.gz"
RAW_NAME="kernel-13.60-live.bin"
FINAL_BIN="wp3_boot/kernel_raw.bin"

URL_PRIMARY="https://github.com/terrafirma2021/ps5-13.60-kernel-dump/raw/main/kernel-13.60-live.bin.gz"
URL_LFS_DIRECT="https://media.githubusercontent.com/media/terrafirma2021/ps5-13.60-kernel-dump/main/kernel-13.60-live.bin.gz"

echo "=== [PS5 13.60 QEMU Boot Kit Auto-Builder] ==="

# 1. Check if already built and valid
if [ -f "$FINAL_BIN" ] && [ -f "build_kernel.py" ]; then
    echo "[*] Checking existing kernel binary..."
    if python3 build_kernel.py "$FINAL_BIN" 2>/dev/null; then
        echo "[+] Kernel is already built and verified! Nothing to do."
        exit 0
    fi
fi

# 2. Check if build_kernel.py exists
if [ ! -f "build_kernel.py" ]; then
    echo "[!] Error: build_kernel.py not found in current directory!" >&2
    exit 1
fi

# 3. Check / Download raw dump
if [ ! -f "$RAW_NAME" ]; then
    if [ ! -f "$GZ_NAME" ]; then
        echo "[*] Downloading base kernel dump from GitHub..."
        if command -v curl >/dev/null 2>&1; then
            curl -fSL --progress-bar "$URL_PRIMARY" -o "$GZ_NAME"
        elif command -v wget >/dev/null 2>&1; then
            wget -q --show-progress "$URL_PRIMARY" -O "$GZ_NAME"
        else
            echo "[!] Error: Neither curl nor wget is installed." >&2
            exit 1
        fi

        # Check if downloaded file is a Git-LFS text pointer
        if grep -q "oid sha256:" "$GZ_NAME" 2>/dev/null; then
            echo "[*] Detected Git-LFS pointer. Fetching binary payload via media endpoint..."
            if command -v curl >/dev/null 2>&1; then
                curl -fSL --progress-bar "$URL_LFS_DIRECT" -o "$GZ_NAME"
            else
                wget -q --show-progress "$URL_LFS_DIRECT" -O "$GZ_NAME"
            fi
        fi
    fi

    echo "[*] Decompressing $GZ_NAME..."
    gzip -dc "$GZ_NAME" > "$RAW_NAME"
    echo "[+] Extracted base dump: $RAW_NAME"
fi

# 4. Apply binary patches using your generated builder
echo "[*] Applying binary diff patches..."
python3 build_kernel.py "$RAW_NAME"

# 5. Verify target binary
if [ -f "$FINAL_BIN" ]; then
    echo "=================================================="
    echo "[+] SUCCESS: $FINAL_BIN generated and ready to boot!"
    echo "=================================================="
else
    echo "[!] Error: Kernel generation failed." >&2
    exit 1
fi
