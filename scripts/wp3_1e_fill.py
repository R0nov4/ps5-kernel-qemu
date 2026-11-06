import sys
sys.path.insert(0, "./scripts")
from wp1_lib import disasm, read_u64, read_u32, read, cstr, rip_target, in_data, in_text

# 1) metadata getter: how does it access modulep?
print("===== metadata getter 0x9edfd670 (first 0x100) =====")
for ins in disasm(0xffffffff9edfd670, 0x100, 120):
    t = rip_target(ins); a = ""
    if t is not None:
        s = cstr(t)
        extra = ""
        if in_data(t):
            v = read_u64(t)
            if v: extra = f" live=0x{v:x}"
        a = f" ; -> 0x{t:x}" + (f" '{s}'" if s else "") + extra
    print(f"0x{ins.address:x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}{a}")
    if ins.mnemonic == "ret": break

# 2) scan pmap_bootstrap fill region for how PTE entries are written (VA mode)
print("\n===== pmap_bootstrap fill code scan: indirect/absolute memory writes =====")
for ins in disasm(0xffffffff9eccbf50, 0x3000, 3000):
    if ins.mnemonic == "ret": break
    # instructions that write memory through registers (table fill)
    if ins.mnemonic == "mov" and ("qword ptr [r" in ins.op_str and (", r" in ins.op_str or ", e" in ins.op_str)):
        # writes through register pointers
        if any(x in ins.op_str.split(",")[0] for x in ["rax","rbx","rcx","rdx","rdi","rsi","rbp","r8","r9","r10","r11","r12","r13","r14","r15"]):
            pass # too many; only print ones with page-ish constants nearby
    # capture: movabs constants that look like PTE bits (0x8000000000000063 = RW+X+P etc)
    if ins.mnemonic == "movabs":
        try: v = int(ins.op_str.split(", ")[1], 16)
        except: continue
        if v & 1 and v > 0x1000000000000:
            print(f"0x{ins.address:x}  {ins.mnemonic} {ins.op_str}   <<<< PTE-ish constant")

# 3) find where recursive slot / PML4 self-reference is set in fill code
print("\n===== search for 'or [reg], 0x8000000000000091-ish' / self-ref patterns =====")
for ins in disasm(0xffffffff9eccbf50, 0x3000, 3000):
    if ins.mnemonic == "ret": break
    if ins.mnemonic == "or" and ("0x8000000000000000" in ins.op_str or "0x80000000000000" in ins.op_str):
        print(f"0x{ins.address:x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}")
    if ins.mnemonic in ("or","add") and ins.op_str.startswith("qword ptr [r") and "0x91" in ins.op_str:
        print(f"0x{ins.address:x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}   <<<< +PG flags 0x91?")

# 4) 'Testing system memory' loop — what VAs does it touch?
print("\n===== Testing-system-memory loop 0x9edf9a00..0x9edf9c76 =====")
for ins in disasm(0xffffffff9edf9a00, 0x280, 300):
    t = rip_target(ins); a = ""
    if t is not None:
        s = cstr(t)
        a = f" ; -> 0x{t:x}" + (f" '{s}'" if s else "")
    mark = " <<<ACCESS" if (ins.mnemonic in ("mov","movzx","movsx") and "ptr [r" in ins.op_str and "-" not in ins.op_str.split(",")[0]) else ""
    print(f"0x{ins.address:x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}{a}{mark}")
