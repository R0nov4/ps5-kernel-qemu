target remote :1234
set pagination off
set confirm off
set architecture i386:x86-64

b *0xffffffff9e8f3d03
c

echo \n=== THE FAKE KERNEL MAP @ parent ===\n
set $parent = 0xffff8e773f300000
x/24gx $parent
echo \n=== the submap candidate (rbx) ===\n
x/8gx $rbx
echo \n=== size (r12) and hint fields ===\n
info registers r12 r13 r14 r15
kill
quit
