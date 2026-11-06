import sys
sys.path.insert(0, "./scripts")
from wp1_lib import disasm, read_u64, cstr, rip_target, in_data

KNOWN = {0xffffffff9e64d410:"printf", 0xffffffff9f08aa10:"panic", 0xffffffff9e648ff0:"bzero"}
def dump(va, name, nbytes=0x300):
    print(f"\n===== {name} @ 0x{va:x} =====")
    for ins in disasm(va, nbytes, 400):
        t = rip_target(ins); a = ""
        if t is not None:
            s = cstr(t)
            a = f" ; -> 0x{t:x}" + (f" '{s}'" if s else "") + (f" live=0x{read_u64(t):x}" if in_data(t) and read_u64(t) else "")
        if ins.mnemonic in ("call","jmp") and ins.op_str.startswith("0x") and int(ins.op_str,16) in KNOWN:
            a += f" ; = {KNOWN[int(ins.op_str,16)]}"
        print(f"0x{ins.address:x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}{a}")
        if ins.mnemonic == "ret": break

dump(0xffffffff9e995130, "cond_fn_1 (pmap param gate A)")
dump(0xffffffff9eebc9a0, "cond_fn_2 (pmap param gate B, arg 0xc)")
dump(0xffffffff9edf85d0, "maxmem_getter")
dump(0xffffffff9edfbec0, "region_fn")
