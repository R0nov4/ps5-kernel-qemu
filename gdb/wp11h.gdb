set pagination off
set confirm off
target remote :1234
break *0xffffffff9e642a90
continue

printf "\n===== AT BTEXT — mbi inspection =====\n"
python
import gdb
inf = gdb.selected_inferior()
def rd(addr, n):
    return bytes(inf.read_memory(addr, n))
def rv(addr, n=8, label=""):
    try:
        data = rd(addr, n * 8)
        print(f"--- {label}")
        for i in range(n):
            q = int.from_bytes(data[i*8:(i+1)*8], "little")
            print(f"  {addr + i*8:#x}: {q:#018x}")
    except gdb.MemoryError:
        print(f"  {label}: UNMAPPED")

# trampoline bss: mbi_ptr @ 0x108250
try:
    mbi = int.from_bytes(rd(0x108250, 4), "little")
    print(f"mbi_ptr = {mbi:#x}")
    flags = int.from_bytes(rd(mbi, 4), "little")
    print(f"mbi flags = {flags:#x} (bit6 mmap: {bool(flags & 0x40)})")
    mmap_len = int.from_bytes(rd(mbi + 0x2c, 4), "little")
    mmap_addr = int.from_bytes(rd(mbi + 0x30, 4), "little")
    print(f"mmap: addr={mmap_addr:#x} len={mmap_len:#x}")
    # dump entries
    off = 0
    i = 0
    while off < mmap_len and i < 10:
        e = rd(mmap_addr + off, 24)
        size = int.from_bytes(e[0:4], "little")
        base = int.from_bytes(e[4:12], "little")
        ln = int.from_bytes(e[12:20], "little")
        typ = int.from_bytes(e[20:24], "little")
        print(f"  entry[{i}] @{mmap_addr+off:#x}: size={size} base={base:#x} len={ln:#x} end={base+ln:#x} type={typ}")
        if size == 0:
            break
        off += size + 4
        i += 1
except gdb.MemoryError as ex:
    print(f"UNMAPPED: {ex}")
end

detach
quit
