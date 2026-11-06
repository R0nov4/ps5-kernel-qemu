import sys
sys.path.insert(0, "./scripts")
from wp1_lib import disasm, read_u64, read_u32, cstr, rip_target, in_data

KNOWN = {0xffffffff9e64d410:"printf(thunk)", 0xffffffff9f08aa10:"panic", 0xffffffff9e648ff0:"bzero"}

def dis(va, name, maxbytes=0x300, maxins=300, depth_names=None):
    print(f"\n===== {name} @ 0x{va:x} =====")
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
            tgt = int(ins.op_str, 16)
            calls.append(tgt)
            if tgt in KNOWN: a += f" ; = {KNOWN[tgt]}"
        print(f"0x{ins.address:x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}{a}")
        if ins.mnemonic == "ret": break
    return calls

c1 = dis(0xffffffff9e89dd60, "real printf")
print("\nprintf direct calls:", [hex(c) for c in c1])
# follow each callee: look for vprintf/kvprintf pattern
for c in c1[:6]:
    sub = disasm(c, 0x60)
    n = sum(1 for _ in sub)
    print(f"\n--- callee 0x{c:x}: first ins: {sub[0].mnemonic} {sub[0].op_str if sub else 'NONE'} ({n} ins in 0x60)")
