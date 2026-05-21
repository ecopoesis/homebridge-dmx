# Trace UP from the Stick3CryptDmxUniverse factory to find the XHL_Stick3
# device class — where the cipher state is actually initialized.
#
# Known facts:
#   - FUN_100178bb0 = Stick3CryptDmxUniverse factory
#   - Called by FUN_100179050
#   - The cipher object lives at (device + 0x1618), embedded inside the
#     device class. The device's ctor writes the embedded cipher's vptr.
#
# Goal: dump FUN_100179050 + its callers (probably the XHL_Stick3 device's
# methods), and dump the 7 big constructors (2.7-8KB) that we identified as
# touching the encrypt-fn vtables — one of them is XHL_Stick3 itself.

# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT_DIR = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out12')
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


# 1. Caller of Stick3 factory + its callers (one more hop up)
factory_caller = 0x100179050
roots = {'caller_of_factory': factory_caller}
seen = set()
summary = open(os.path.join(OUT_DIR, 'SUMMARY.txt'), 'w')

f = fm.getFunctionAt(addr(factory_caller))
if f:
    seen.add(f.getEntryPoint())
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
    with open(os.path.join(OUT_DIR, 'A_factorycaller_%s_%s.txt' %
                            (f.getEntryPoint(), safe)), 'w') as o:
        dump(f, o)
    summary.write('factory_caller = %s @ %s (size %d)\n' %
                  (f.getName(True), f.getEntryPoint(),
                   f.getBody().getNumAddresses()))
    summary.write('  one-up callers:\n')
    for c in sorted(f.getCallingFunctions(monitor), key=lambda f: f.getEntryPoint()):
        summary.write('    %s @ %s (size %d)\n' %
                      (c.getName(True), c.getEntryPoint(),
                       c.getBody().getNumAddresses()))
        if c.getEntryPoint() in seen: continue
        seen.add(c.getEntryPoint())
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', c.getName(True))[:120]
        with open(os.path.join(OUT_DIR, 'B_oneUp_%s_%s.txt' %
                                (c.getEntryPoint(), safe)), 'w') as o:
            dump(c, o)

# 2. The 7 big constructors that touched encrypt-fn vtables
BIG_CTORS = [
    0x1002385b0,
    0x10027d350,
    0x100283f60,
    0x1002b7360,
    0x1002c1920,
    0x1002c8ac0,
    0x1002ceaf0,
]
summary.write('\n=== Big constructors touching encrypt-fn vtables ===\n')
for fp in BIG_CTORS:
    f = fm.getFunctionAt(addr(fp))
    if f is None: continue
    summary.write('  %s @ %s (size %d)\n' %
                  (f.getName(True), f.getEntryPoint(),
                   f.getBody().getNumAddresses()))
    if f.getEntryPoint() in seen: continue
    seen.add(f.getEntryPoint())
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
    with open(os.path.join(OUT_DIR, 'C_bigctor_%s_%s.txt' %
                            (f.getEntryPoint(), safe)), 'w') as o:
        dump(f, o)

summary.write('\n=== total: %d ===\n' % len(seen))
summary.close()
print('find-stick3-device: %d functions dumped to %s' % (len(seen), OUT_DIR))
