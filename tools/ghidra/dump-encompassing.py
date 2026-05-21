# Walk one more level up the constructor chain — find the device-level
# factory that calls FUN_100179050 (caller of the Stick3CryptDmxUniverse
# factory FUN_100178bb0) and dump constructors that touch offset +0x1618
# (where the cipher object lives).

# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT_DIR = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out11')
try: os.makedirs(OUT_DIR)
except OSError: pass

prog = currentProgram
fm = prog.getFunctionManager()
af = prog.getAddressFactory()
mem = prog.getMemory()
ref_mgr = prog.getReferenceManager()
monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
decomp.openProgram(prog)


def addr(a): return af.getDefaultAddressSpace().getAddress(a)


def dump(func, out):
    out.write('==== %s @ %s ====\n' % (func.getName(True), func.getEntryPoint()))
    out.write('size: %d body bytes\n' % func.getBody().getNumAddresses())
    callees = sorted(set('%s @ %s' % (f.getName(True), f.getEntryPoint())
                         for f in func.getCalledFunctions(monitor)))
    out.write('\n-- callees (%d) --\n' % len(callees))
    for c in callees: out.write('  ' + c + '\n')
    callers = sorted(set('%s @ %s' % (f.getName(True), f.getEntryPoint())
                         for f in func.getCallingFunctions(monitor)))
    out.write('\n-- callers (%d) --\n' % len(callers))
    for c in callers: out.write('  ' + c + '\n')
    out.write('\n-- decompilation --\n')
    res = decomp.decompileFunction(func, 240, monitor)
    if res.decompileCompleted():
        out.write(res.getDecompiledFunction().getC())
    else:
        out.write('(decompilation failed: %s)\n' % res.getErrorMessage())
    out.write('\n')


# Read C string at addr
def cstr(a, maxlen=200):
    out = []
    for i in range(maxlen):
        try:
            b = mem.getByte(a.add(i)) & 0xff
        except Exception:
            break
        if b == 0: break
        out.append(chr(b))
    return ''.join(out)


# All 26 vtables containing FUN_100108200 at slot vt[3] (= site = vt_base+0x18)
# So: vt_base = site - 0x18 = vptr - 0x00 (vptr is at vt_base+8 conceptually,
# but the way we labelled in fixup output, vptr = vt_base+8... let me recompute.
#
# Convention: vtable struct layout:
#     site(typeinfo_ptr) @ X         ← typeinfo rebase row
#     vt[0] @ X + 0x08
#     vt[1] @ X + 0x10
#     vt[2] @ X + 0x18
#     vt[3] @ X + 0x20
#
# So a row "rebase  FUN_100108200" at addr Y means Y stores the encrypt fn.
# If vt[3], then Y = X + 0x20, so X (typeinfo_ptr addr) = Y - 0x20.
# Slot 0 (vptr) is at X + 0x08 = Y - 0x18.

# This was wrong before; the relationship is:
#   if Y = vtable_struct_base + 0x20 (slot 3), and vptr is at +0x08,
#   then vptr = Y - 0x18

ENCRYPT_SLOT_ADDRS = [
    0x100851F50, 0x100A1F168, 0x100A239D0, 0x100A23A70, 0x100B289E0,
    0x100B2EDC8, 0x100B2EE68, 0x100B35D48, 0x100B3C0F8, 0x100B3C198,
    0x100B95940, 0x100B959E0, 0x100B9D7A8, 0x100BA25A8, 0x100BA2648,
    0x100BA9008, 0x100BB0E18, 0x100BB0EB8, 0x100BB7E00, 0x100BBCBC8,
    0x100BBCC68, 0x100BC1920, 0x100BC7D48, 0x100BC7DE8, 0x100C14170,
    0x100C14260,
]

summary = open(os.path.join(OUT_DIR, 'SUMMARY.txt'), 'w')
seen = set()

# For each, read the typeinfo_ptr (at slot_addr - 0x20), then the name string
# referenced from that typeinfo struct (at typeinfo_addr + 0x08).
# Since chained fixups aren't materialized, we have to find the typeinfo via
# Ghidra refs.  Try: getReferencesFrom(typeinfo_ptr_field).
summary.write('=== 26 vtables sharing FUN_100108200 as vt[3] ===\n')
for slot3 in ENCRYPT_SLOT_ADDRS:
    typeinfo_field = slot3 - 0x20
    vptr           = slot3 - 0x18
    summary.write('\n  slot[3] @ 0x%x   vptr=0x%x   typeinfo_ptr_field=0x%x\n' %
                  (slot3, vptr, typeinfo_field))
    # Look at outgoing refs from the typeinfo_field — Ghidra applies refs
    # from chained-fixup rebases for SOME of these.
    refs = list(ref_mgr.getReferencesFrom(addr(typeinfo_field)))
    for r in refs:
        ta = r.getToAddress()
        summary.write('     -> %s\n' % ta)
        # Then refs FROM typeinfo addr's name-ptr field (+8) give the name string
        name_ptr_field = ta.add(8)
        for r2 in ref_mgr.getReferencesFrom(name_ptr_field):
            nstr = cstr(r2.getToAddress(), 200)
            summary.write('        name @ %s : %r\n' % (r2.getToAddress(), nstr))
    # Code refs to vptr = the constructor that uses this vtable
    code_callers = set()
    for r in ref_mgr.getReferencesTo(addr(vptr)):
        f = fm.getFunctionContaining(r.getFromAddress())
        if f is not None:
            code_callers.add(f.getEntryPoint())
    summary.write('     code refs to vptr from %d fn(s):\n' % len(code_callers))
    for ep in sorted(code_callers):
        f = fm.getFunctionAt(ep)
        summary.write('       %s @ %s (size %d)\n' %
                      (f.getName(True), f.getEntryPoint(),
                       f.getBody().getNumAddresses()))
        if ep in seen: continue
        seen.add(ep)
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
        with open(os.path.join(OUT_DIR, 'ctor_vt0x%x_%s_%s.txt' %
                                (vptr, f.getEntryPoint(), safe)), 'w') as o:
            dump(f, o)

# Also: dump FUN_100179050 (caller of Stick3 factory)
for fp in [0x100179050]:
    f = fm.getFunctionAt(addr(fp))
    if f is None: continue
    if f.getEntryPoint() in seen: continue
    seen.add(f.getEntryPoint())
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
    with open(os.path.join(OUT_DIR, 'caller_%s_%s.txt' %
                            (f.getEntryPoint(), safe)), 'w') as o:
        dump(f, o)

summary.write('\n=== total dumped: %d ===\n' % len(seen))
summary.close()
print('dump-encompassing: %d functions dumped to %s' % (len(seen), OUT_DIR))
