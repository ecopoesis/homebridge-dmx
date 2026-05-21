# Dump the ACTUAL encrypt function at FUN_100107950 (Stick3 cipher vt[3]).
# Plus walk callees to find the keystream generator.

# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT_DIR = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out15')
try: os.makedirs(OUT_DIR)
except OSError: pass

prog = currentProgram
fm = prog.getFunctionManager()
af = prog.getAddressFactory()
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

# Full Stick3 cipher vtable @ 0x10095F830 (typeinfo_ptr):
ROOTS = {
    'vt0_FUN_100177990':  0x100177990,
    'vt1_FUN_100177CB0':  0x100177CB0,
    'vt2_FUN_100106290':  0x100106290,
    'vt3_REAL_ENCRYPT_FUN_100107950': 0x100107950,
    'vt4_FUN_1001C0650':  0x1001C0650,
    'vt5_FUN_1001C0A50':  0x1001C0A50,
    'vt6_FUN_1001C0CF0':  0x1001C0CF0,
    'vt7_FUN_100180E90':  0x100180E90,
}

seen = set()
summary = open(os.path.join(OUT_DIR, 'SUMMARY.txt'), 'w')

for label, fp in ROOTS.items():
    f = fm.getFunctionAt(addr(fp)) or fm.getFunctionContaining(addr(fp))
    if f is None:
        summary.write('  %s 0x%x  (no fn)\n' % (label, fp))
        continue
    summary.write('  %-40s = %s @ %s  size=%d  callees=%d\n' %
                  (label, f.getName(True), f.getEntryPoint(),
                   f.getBody().getNumAddresses(),
                   len(set(f.getCalledFunctions(monitor)))))
    if f.getEntryPoint() in seen: continue
    seen.add(f.getEntryPoint())
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
    with open(os.path.join(OUT_DIR, '%s_%s_%s.txt' %
                            (label, f.getEntryPoint(), safe)), 'w') as o:
        dump(f, o)

# Walk into real-encrypt's callees
enc = fm.getFunctionAt(addr(0x100107950))
if enc:
    summary.write('\n=== depth-1 callees of real encrypt fn ===\n')
    for c in sorted(enc.getCalledFunctions(monitor), key=lambda f: f.getEntryPoint()):
        summary.write('  callee: %s @ %s (size %d)\n' %
                      (c.getName(True), c.getEntryPoint(),
                       c.getBody().getNumAddresses()))
        if c.getEntryPoint() in seen: continue
        seen.add(c.getEntryPoint())
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', c.getName(True))[:120]
        with open(os.path.join(OUT_DIR, 'depth1_%s_%s.txt' %
                                (c.getEntryPoint(), safe)), 'w') as o:
            dump(c, o)

summary.write('\n=== total: %d ===\n' % len(seen))
summary.close()
print('dump-real-encrypt: %d functions dumped to %s' % (len(seen), OUT_DIR))
