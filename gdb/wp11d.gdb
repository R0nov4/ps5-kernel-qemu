set pagination off
set confirm off
target remote :1234

break *0xffffffff9e82d7f0
commands
  silent
  printf "fn1 queue-init: obj=%p tmpl=%p idx=%d\n", $rdi, $rsi, $edx
  continue
end

break *0xffffffff9e8b6c71
continue

printf "\n===== crash state =====\n"
info registers rdi rsi r13 r14

printf "\n===== queue template descriptor (rsi at crash = 0xffffffffa1978860? dump template fields) =====\n"
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

# queue ptr array region in .data
rv(0xffffffffa18ea800, "queue array region 0xa18ea800", 32)
rv(0xffffffffa18eae00, "queue array region 0xa18eae00", 32)
rv(0xffffffffa18eb000, "queue array region 0xa18eb000", 20)
end

detach
quit
