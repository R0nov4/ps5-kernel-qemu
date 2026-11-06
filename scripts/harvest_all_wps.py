#!/usr/bin/env python3
import os, shutil, hashlib

SRC_ROOT = os.path.expanduser("~/lol")
DST_ROOT = os.path.expanduser("~/ps5-13.60-qemu-boot")

# پسوندهایی که ارزش علمی، مستندات و سورس‌کد دارند (بدون باینری‌های سنگین و تکراری)
KEEP_EXTS = {".py", ".sh", ".asm", ".inc", ".ld", ".gdb", ".md", ".txt", ".json"}
SKIP_DIRS = {"bios", ".git", "__pycache__"}
SKIP_FILES = {"kernel_raw.bin", "wp20_golden_kernel_raw.bin", "PS5UPDATE.pup", "ps5_kernel_13.60_dump.bin"}

os.makedirs(os.path.join(DST_ROOT, "scripts"), exist_ok=True)
os.makedirs(os.path.join(DST_ROOT, "gdb"), exist_ok=True)
os.makedirs(os.path.join(DST_ROOT, "docs_reports"), exist_ok=True)

copied = 0
updated = 0

for root, dirs, files in os.walk(SRC_ROOT):
    # نرفتن داخل پوشه مقصد اگر داخل همان مسیر باشد
    if os.path.abspath(root).startswith(os.path.abspath(DST_ROOT)):
        continue
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

    for f in files:
        if f in SKIP_FILES:
            continue
        ext = os.path.splitext(f)[1].lower()
        # نگه‌داشتن لاگ‌های خاصِ مراحل مختلف (مثل serial.log.wp18، wp20 و ...)
        is_milestone_log = f.startswith("serial.log.wp") or f.startswith("wp3_4_first")
        if ext not in KEEP_EXTS and not is_milestone_log:
            continue

        src_path = os.path.join(root, f)
        rel_parent = os.path.basename(root)

        # تعیین پوشهٔ مقصدِ تمیز بر اساس نوع فایل
        if rel_parent in ("ps5_wp1", "ps5_wp2", "ps5_wp3"):
            dst_dir = os.path.join(DST_ROOT, rel_parent)
        elif ext == ".gdb" or rel_parent == "gdb" or f.startswith("gdb_"):
            dst_dir = os.path.join(DST_ROOT, "gdb")
        elif ext in (".py", ".sh", ".asm", ".inc", ".ld"):
            # اسکریپت‌های اصلی اجرای ریشه در ریشه می‌مانند، بقیه در scripts/
            if f in ("run.sh",):
                dst_dir = DST_ROOT
            elif f in ("trampoline.asm", "meta.inc", "params.inc", "patches.inc", "tramp.ld", "probe.ld"):
                dst_dir = os.path.join(DST_ROOT, "wp3_boot")
            else:
                dst_dir = os.path.join(DST_ROOT, "scripts")
        elif f.startswith("wp") and (f.endswith("_report.txt") or f.endswith("_stages.txt") or f.endswith("_scan.txt") or f.endswith("correction.txt") or f.endswith("constants.json")):
            dst_dir = os.path.join(DST_ROOT, "docs_reports")
        elif is_milestone_log:
            dst_dir = os.path.join(DST_ROOT, "docs_reports")
        elif f == "worklog.md":
            # برای worklog.md بزرگ‌ترین و کامل‌ترین نسخه را نگه می‌داریم
            dst_p = os.path.join(DST_ROOT, "worklog_full_history.md")
            if not os.path.exists(dst_p) or os.path.getsize(src_path) > os.path.getsize(dst_p):
                shutil.copy2(src_path, dst_p)
            continue
        else:
            continue

        os.makedirs(dst_dir, exist_ok=True)
        dst_path = os.path.join(dst_dir, f)

        # اگر فایل وجود ندارد، یا نسخهٔ پیدا شده جدیدتر/کامل‌تر است کپی کن
        if not os.path.exists(dst_path):
            shutil.copy2(src_path, dst_path)
            copied += 1
        else:
            if os.path.getsize(src_path) > os.path.getsize(dst_path):
                shutil.copy2(src_path, dst_path)
                updated += 1

print(f"[+] Harvest complete! Added {copied} unique files, upgraded {updated} files to their fullest version.")
