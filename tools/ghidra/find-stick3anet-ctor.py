# Find XHL_Stick3ANet device constructor + trace cipher init at this+0x1618.

# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT_DIR = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out14')
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


# Primary Stick3ANet vptr = slot 0 of vtable @ 0x10095EF70 (typeinfo_ptr field)
# So vptr stored in instances = 0x10095EF70 + 8 = 0x10095EF78
VPTRS = {
    'Stick3ANet_primary': 0x10095EF78,
}

seen = set()
summary = open(os.path.join(OUT_DIR, 'SUMMARY.txt'), 'w')

for label, vptr in VPTRS.items():
    summary.write('\n#### %s   vptr=0x%x\n' % (label, vptr))
    code_refs = set()
    for r in ref_mgr.getReferencesTo(addr(vptr)):
        f = fm.getFunctionContaining(r.getFromAddress())
        if f is not None:
            code_refs.add(f.getEntryPoint())
    summary.write('  code refs from %d fn(s):\n' % len(code_refs))
    for ep in sorted(code_refs):
        f = fm.getFunctionAt(ep)
        summary.write('    %s @ %s (size %d)\n' %
                      (f.getName(True), f.getEntryPoint(),
                       f.getBody().getNumAddresses()))
        if ep in seen: continue
        seen.add(ep)
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
        with open(os.path.join(OUT_DIR, '%s_%s_%s.txt' %
                                (label, f.getEntryPoint(), safe)), 'w') as o:
            dump(f, o)

summary.write('\n=== total: %d ===\n' % len(seen))
summary.close()
print('find-stick3anet-ctor: %d functions dumped to %s' % (len(seen), OUT_DIR))
