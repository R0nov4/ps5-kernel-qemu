#!/bin/bash
# wp18_boot.sh — boot the kit and report the frontier (crash IP / CR2 / gate)
cd ./kit_build
bash run.sh 300 > /dev/null 2>&1 || true
echo "=== frontier ==="
grep -a -m1 "fault virtual address" serial.log || true
grep -a -m1 "instruction pointer" serial.log || echo "(no crash — clean boot!)"
grep -a -m1 "trap number" serial.log || true
grep -a -m1 "panic:" serial.log || true
grep -a -c "can't re-use a leaf" serial.log | xargs echo "sysctl leaf lines:"
grep -a -m1 "Fatal trap" serial.log || true
echo "=== last 12 lines before trap ==="
grep -a -n -B1 "Fatal trap\|kernel trap\|panic:" serial.log | head -6 || true
tail -30 serial.log | head -18
wc -l serial.log | xargs echo "serial lines:"
