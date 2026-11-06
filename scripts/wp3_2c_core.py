import sys
sys.path.insert(0, "./scripts")
from wp1_lib import disasm, read_u64, read_u32, cstr, rip_target, in_data

def dis(va, name, maxbytes=0x500, maxins=500):
    print(f"===== {name} @ 0x{va:x} =====")
    calls = []
    for ins in disasm(va, maxbytes, maxins):
        t = rip_target(ins); a = ""
        if t is not None:
            s = cstr(t)
            extra = ""
            if in_data(t):
                v = read_u64(t)
                if v: extra = f" live=0x{v:x}"
            a = f" ; -> 0x{t:x}" + (f" '{s}'" if s else "") + extra
        if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
            calls.append(int(ins.op_str, 16))
        print(f"0x{ins.address:x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}{a}")
        if ins.mnemonic == "ret": break
    print("calls:", [hex(c) for c in calls])
    return calls

c = dis(0xffffffff9e89da20, "kvprintf_core")
