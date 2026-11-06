set pagination off
set confirm off
target remote :1234
break *0xffffffff9e8b6c71
continue

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

print("===== SIX VIEWS of zone74 (base 0x22B0 offset) =====")
rv(0xffffffff80f122b0, "A: pool VA pre-slide  (tramp KVA -> phys 0xF122B0)")
rv(0xffffffff9f0f22b0, "B: pool VA slid       (.data + 0x4422b0)")
rv(0xffff8e773f0122b0, "C: DMAP seed view     (known zeros)")
rv(0xffffffffbf122b0, "D: KVA-window alias of seed phys 0x3F122B0")
rv(0xffff8e7700f122b0, "E: DMAP of SMAP hole phys 0xF122B0")
rv(0xffffffff80f10000, "F: pool base pre-slide first qwords", 4)
rv(0xffffffff9f0f0000, "G: pool base slid first qwords", 4)
print("===== runtime PREINIT_POOL =====")
rv(0xffffffffa1f37e50, "[0xa1f37e50]", 1)
print("===== stack slots frame3/4 locals =====")
rv(0xffffffffa2228760, "fn2 frame locals", 6)
end

detach
quit
