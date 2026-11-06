set pagination off
set confirm off
set architecture i386:x86-64
set remotetimeout 600
target remote localhost:1234
break *0xffffffff9e642a90
break *0xffffffff9ecdbe27
continue
printf "\n=== btext ===\n"
continue
printf "\n=== AT CRASH 0x9ecdbe27 ===\n"
info registers r14 rdx rax
printf "\n=== kernel PDPT (phys 0x22230000) DMAP entries [0x1DC..0x1E0] ===\n"
set $pdpt = 0xffff8e7722230000
x/8gx $pdpt + 0x1dc*8
printf "\n=== kernel PML4 (find via L4 cache) — dump DMAP slot ===\n"
printf "[0xa1f39018] L4 cache = %p\n", *(unsigned long long*)0xffffffffa1f39018
printf "\n=== the garbage PDE: PD for [1GB,2GB) ===\n"
# PDPT[0x1DD] should point at the PD for phys [1GB,2GB)
set $pdpt_entry = *(unsigned long long*)($pdpt + 0x1dd*8)
printf "PDPT[0x1DD] = %p\n", $pdpt_entry
set $pd = 0xffff8e7700000000 + ($pdpt_entry & 0xffffffffff000)
printf "PD base = %p\n", $pd
printf "PD entries around idx %d (phys 0x7fd8c000 >> 21):\n", (0x7fd8c000 >> 21) & 0x1ff
x/8gx $pd + ((0x7fd8c000 >> 21) & 0x1ff & 0xfffffff8)*8
printf "\n=== PDPT[0x1DC] (the [0,1GB) PD) for comparison ===\n"
set $pdpt_entry0 = *(unsigned long long*)($pdpt + 0x1dc*8)
printf "PDPT[0x1DC] = %p\n", $pdpt_entry0
set $pd0 = 0xffff8e7700000000 + ($pdpt_entry0 & 0xffffffffff000)
printf "PD0[0..3] = \n"
x/4gx $pd0
printf "\n=== attr fn caller frame ===\n"
printf "return addr [rbp+8] = %p\n", *(unsigned long long*)($rbp+8)
printf "attr fn rdi obj (from [rbp-based]) — dump stack around:\n"
x/16gx $rbp-0x60
kill
quit
