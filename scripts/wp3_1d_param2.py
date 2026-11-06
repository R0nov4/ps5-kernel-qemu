import sys
sys.path.insert(0, "./scripts")
from wp1_lib import disasm, read_u64, read_u32, cstr, rip_target, in_data

# full disasm of param_reader without early stop; look for interesting instructions
print("===== param_reader 0x9efd3f10 full =====")
for ins in disasm(0xffffffff9efd3f10, 0x600, 600):
    t = rip_target(ins); a = ""
    if t is not None:
        s = cstr(t)
        extra = ""
        if in_data(t):
            v = read_u64(t)
            if v: extra = f" live=0x{v:x}"
        a = f" ; -> 0x{t:x}" + (f" '{s}'" if s else "") + extra
    mark = ""
    if ins.mnemonic in ("call","out","in","vmmcall","rdmsr","wrmsr","cpuid","invlpg") or "cr3" in ins.op_str or "movbe" == ins.mnemonic:
        mark = " <<<"
    print(f"0x{ins.address:x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}{a}{mark}")
    if ins.mnemonic == "ret":
        break
