# xref the "software" cstring (0x1007e4f83) — the function that assigns it to
# a device also assigns the adjacent auth key.
# @category Stick
import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
OUT = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out-swxref')
try: os.makedirs(OUT)
except OSError: pass
prog = currentProgram; fm = prog.getFunctionManager(); af = prog.getAddressFactory()
rm = prog.getReferenceManager(); monitor = ConsoleTaskMonitor()
decomp = DecompInterface(); decomp.openProgram(prog)
def addr(a): return af.getDefaultAddressSpace().getAddress(a)
def dec(f):
    r = decomp.decompileFunction(f, 240, monitor)
    return r.getDecompiledFunction().getC() if r.decompileCompleted() else '(fail)\n'
seen=set()
for target in [0x1007e4f83]:
    for r in rm.getReferencesTo(addr(target)):
        f = fm.getFunctionContaining(r.getFromAddress())
        if f is None or str(f.getEntryPoint()) in seen: continue
        seen.add(str(f.getEntryPoint()))
        safe = re.sub(r'[^A-Za-z0-9._-]','_',f.getName(True))[:70]
        with open(os.path.join(OUT,'xref_%s_%s.txt'%(f.getEntryPoint(),safe)),'w') as o:
            o.write('==== %s @ %s (from %s) ====\n'%(f.getName(True),f.getEntryPoint(),r.getFromAddress()))
            o.write(dec(f))
print('dump-swxref: %d functions -> %s'%(len(seen),OUT))
