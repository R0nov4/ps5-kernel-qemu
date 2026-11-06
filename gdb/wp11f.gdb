set pagination off
set confirm off
target remote :1234

watch *(unsigned long *)0xa18eafc0
commands
  silent
  printf "WATCH [zone2+0x80] -> %p rip=%p\n", *(unsigned long*)0xa18eafc0, $rip
  continue
end

break *0xffffffff9e8b6c71
continue

printf "\n===== ZONES AT CRASH =====\n"
python
import gdb
inf = gdb.selected_inferior()
def rv(addr, label, n=8):
    print(f"--- {label}")
    try:
        data = bytes(inf.read_memory(addr, n * 8))
        for i in range(n):
            q = int.from_bytes(data[i*8:(i+1)*8], "little")
            print(f"  {addr + i*8:#x}: {q:#018x}")
    except gdb.MemoryError:
        print("  UNMAPPED")
rv(0xffffffffa18ead40, "zone1 @0xa18ead40 (0x120 bytes)", 36)
rv(0xffffffffa18eaf40, "zone2 @0xa18eaf40 (0x120 bytes)", 36)
rv(0xffffffffa18ea740, "zone1 object 0xa18ea740", 16)
rv(0xffffffffa18ea790, "zone1 object 0xa18ea790", 16)
end

detach
quit
