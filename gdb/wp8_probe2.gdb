set architecture i386:x86-64
target remote localhost:1234
break *0xffffffff9ef7a475
continue
echo \n=== probe2: FULL thread0 stack to top ===\n
x/92gx $rsp
echo \n=== struct at slot0 ptr 0x9fec0400 ===\n
x/5gx 0xffffffff9fec0400
echo \n=== first slots of sysinit array ===\n
x/16gx 0xffffffff9fe51fb0
echo \n=== boothowto-ish mi_startup window globals ===\n
x/gx 0xffffffffa19781b0
x/gx 0xffffffffa19781a8
detach
quit
