#!/bin/bash
# WP6-BT2: at first strtoul-thunk hit, dump the full stack to find the
# outer-loop caller frames (code addresses above the engine frames).
cd .
export LD_LIBRARY_PATH=./qemu-local/root/usr/lib/x86_64-linux-gnu
GDB=./qemu-local/root/usr/bin/gdb
QEMU=./qemu-local/root/usr/bin/qemu-system-x86_64

cat > /tmp/wp6_bt2.gdb <<'EOF'
set pagination off
set confirm off
set height 0
target remote localhost:1234
hbreak *0xffffffff9e65b880
continue
printf "\n=== FIRST HIT: full stack dump ===\n"
printf "rsp=%p rbp=%p\n", $rsp, $rbp
x/128gx $rsp
printf "\n=== rbp area ===\n"
x/8gx $rbp-0x10
printf "\n=== above rbp (caller frames) ===\n"
x/64gx $rbp+0x8
kill
EOF

rm -f wp3_boot/wp6_bt2.log
$QEMU -L ./qemu-local/root/usr/share/qemu \
  -M pc -cpu EPYC -m 2G -smp 1 \
  -kernel wp3_boot/trampoline.elf -initrd wp3_boot/kernel_raw.bin \
  -display none -serial null -monitor none \
  -chardev file,id=dbg,path=/dev/null \
  -device isa-debugcon,iobase=0x402,chardev=dbg \
  -no-reboot -S -gdb tcp::1234 2>/dev/null &
QPID=$!
sleep 1
timeout 90 $GDB -batch -x /tmp/wp6_bt2.gdb > wp3_boot/wp6_bt2.log 2>&1
kill $QPID 2>/dev/null; wait 2>/dev/null

# extract CODE addresses (0xffffffff9e3f0000..0xffffffffa0600000) from the dump
python3 - <<'PYEOF'
import re
log = open("wp3_boot/wp6_bt2.log", errors="ignore").read()
qs = re.findall(r"0x([0-9a-f]{16})", log)
seen = []
for h in qs:
    v = int(h, 16)
    if 0xffffffff9e3f0000 <= v < 0xffffffffa0600000 and v not in seen:
        seen.append(v)
print("code addrs on stack (in order):")
for v in seen:
    print(f"  0x{v:x}")
PYEOF
