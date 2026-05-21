# Find every function that references the MD5 init constants table
# at 0x1007C0290. That table is the H0 = {A,B,C,D} = {0x67452301, ...}.
# The function reading it IS the MD5 init / compute function. From there
# we can find callers and identify the KDF that produces the AES key.

# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT_DIR = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out18')
try: os.makedirs(OUT_DIR)
except OSError: pass

prog = currentProgram
fm = prog.getFunctionManager()
af = prog.getAddressFactory()
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


seen = set()
summary = open(os.path.join(OUT_DIR, 'SUMMARY.txt'), 'w')

# Find any function that references the MD5 init table at 0x1007C0290.
MD5_ADDR = 0x1007C0290
summary.write('Refs to MD5 init constants @ 0x%x\n\n' % MD5_ADDR)
refs = list(ref_mgr.getReferencesTo(addr(MD5_ADDR)))
summary.write('total refs: %d\n' % len(refs))
code_callers = set()
for r in refs:
    fa = r.getFromAddress()
    rt = r.getReferenceType().getName()
    f = fm.getFunctionContaining(fa)
    if f is not None:
        code_callers.add(f.getEntryPoint())
        summary.write('  ref @ %s (%s) -> fn %s @ %s\n' %
                      (fa, rt, f.getName(True), f.getEntryPoint()))
    else:
        summary.write('  ref @ %s (%s) - no fn\n' % (fa, rt))

# Dump each MD5-using function + its callers (one hop UP)
summary.write('\n=== MD5-init users + their callers ===\n')
for ep in sorted(code_callers):
    f = fm.getFunctionAt(ep)
    if f is None: continue
    summary.write('\n  MD5_user: %s @ %s (size %d)\n' %
                  (f.getName(True), f.getEntryPoint(),
                   f.getBody().getNumAddresses()))
    summary.write('    callers of this fn:\n')
    for c in sorted(f.getCallingFunctions(monitor), key=lambda f: f.getEntryPoint()):
        summary.write('      %s @ %s (size %d)\n' %
                      (c.getName(True), c.getEntryPoint(),
                       c.getBody().getNumAddresses()))
    # Dump the MD5 user itself
    if ep not in seen:
        seen.add(ep)
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
        with open(os.path.join(OUT_DIR, 'md5_user_%s_%s.txt' %
                                (f.getEntryPoint(), safe)), 'w') as o:
            dump(f, o)
    # Dump each caller too
    for c in f.getCallingFunctions(monitor):
        if c.getEntryPoint() in seen: continue
        seen.add(c.getEntryPoint())
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', c.getName(True))[:120]
        with open(os.path.join(OUT_DIR, 'md5_caller_%s_%s.txt' %
                                (c.getEntryPoint(), safe)), 'w') as o:
            dump(c, o)

summary.write('\n=== total: %d ===\n' % len(seen))
summary.close()
print('find-md5: %d functions dumped to %s' % (len(seen), OUT_DIR))
