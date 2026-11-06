set pagination off
set confirm off
set architecture i386:x86-64
set remotetimeout 600
target remote localhost:1234
break *0xffffffff9e642a90
continue
printf "btext — searching for real ACPI tables\n"
printf "EBDA base: %p\n", (unsigned short)*(unsigned short*)0x40e << 10
printf "RSDP scan in EBDA:\n"
set $ebda = (unsigned short)*(unsigned short*)0x40e << 10
set $i = 0
while $i < 0x400
  if *(unsigned int*)($ebda + $i) == 0x20445352
    printf "FOUND RSDP at %p\n", $ebda + $i
    printf "  rsdt ptr = %p\n", *(unsigned int*)($ebda + $i + 0x10)
    printf "  revision = %d\n", *(unsigned char*)($ebda + $i + 0xf)
  end
  set $i = $i + 4
end
printf "scan [0xE0000, 0x100000):\n"
set $i = 0xE0000
while $i < 0x100000
  if *(unsigned int*)$i == 0x20445352
    printf "FOUND RSDP at %p\n", $i
    printf "  rsdt ptr = %p\n", *(unsigned int*)($i + 0x10)
  end
  set $i = $i + 4
end
printf "RSDT content check at 0x7ffe2441 via DMAP:\n"
x/4gx 0xffff8e777ffe2441
printf "XSDT check 0x7ffe2440:\n"
x/4gx 0xffff8e777ffe2440
kill
quit
