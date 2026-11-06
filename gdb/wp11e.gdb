set pagination off
set confirm off
target remote :1234

break *0xffffffff9e82b260
commands
  silent
  printf "ALLOC fn5: zone=%p backend=[%p] ctx=[%p] init=[%p] flags=%d cnt=%d\n", $rdi, *(void**)($rdi+0xb0), *(void**)($rdi+0xc0), *(void**)($rdi+0xa0), $rsi, $edx
  continue
end

break *0xffffffff9e82d7f0
commands
  silent
  printf "QINIT fn1: obj=%p tmpl=%p idx=%d\n", $rdi, $rsi, $edx
  continue
end

watch *(unsigned long *)0xa18ea8f8
commands
  silent
  printf "WATCH qreg-8f8 -> %p (rip=%p)\n", *(unsigned long*)0xa18ea8f8, $rip
  continue
end

break *0xffffffff9e8b6c71
continue

printf "\n===== CRASH STATE =====\n"
info registers rdi rsi r13 r14 rbx
python
import gdb
inf = gdb.selected_inferior()
def rv(addr, label, n=6):
    print(f"--- {label}")
    try:
        data = bytes(inf.read_memory(addr, n * 8))
        for i in range(n):
            q = int.from_bytes(data[i*8:(i+1)*8], "little")
            print(f"  {addr + i*8:#x}: {q:#018x}")
    except gdb.MemoryError:
        print("  UNMAPPED")
rv(0xffffffffa18ea8c8, "zone-holder [0xa18ea8c8]", 1)
rv(0xffffffffa18ea8f8, "qreg-8f8", 1)
rv(0xffffffffa18ea828, "qreg-828", 1)
end

detach
quit
