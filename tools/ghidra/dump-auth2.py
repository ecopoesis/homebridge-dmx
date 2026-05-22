# Decompile the 0x48 body builder (FUN_1001ee530), the 0x47 body builder
# (FUN_1001ee730), the packet wrapper (FUN_1001e3890), and authenticate()'s
# caller (FUN_10019e4d0) — to see exactly what the 0x48 auth message contains.
# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out-auth2')
try: os.makedirs(OUT)
except OSError: pass

prog = currentProgram
fm = prog.getFunctionManager()
af = prog.getAddressFactory()
monitor = ConsoleTaskMonitor()
decomp = DecompInterface(); decomp.openProgram(prog)
def addr(a): return af.getDefaultAddressSpace().getAddress(a)

def decompile(f):
    r = decomp.decompileFunction(f, 240, monitor)
    return r.getDecompiledFunction().getC() if r.decompileCompleted() else '(fail)\n'

seen = set()
def dump(fp, label, depth=0):
    f = fm.getFunctionAt(addr(fp)) or fm.getFunctionContaining(addr(fp))
    if f is None or str(f.getEntryPoint()) in seen: return
    seen.add(str(f.getEntryPoint()))
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:60]
    callees = sorted(set(f.getCalledFunctions(monitor)), key=lambda x: str(x.getEntryPoint()))
    with open(os.path.join(OUT, '%s_%s.txt' % (label, f.getEntryPoint())), 'w') as o:
        o.write('==== %s @ %s (%d bytes) ====\n' %
                (f.getName(True), f.getEntryPoint(), f.getBody().getNumAddresses()))
        o.write('callees: ' + ', '.join('%s' % c.getEntryPoint() for c in callees) + '\n\n')
        o.write(decompile(f))
    # one level of non-libc callees for the body builders
    if depth > 0:
        for c in callees:
            nm = c.getName(True)
            if nm.startswith('_') or 'std::' in nm or 'operator' in nm: continue
            dump(int(str(c.getEntryPoint()), 16), label + '_c', depth - 1)

for fp, label in [(0x1001ee530, 'build_0x48'),
                  (0x1001ee730, 'build_0x47'),
                  (0x1001e3890, 'packet_wrap'),
                  (0x10019e4d0, 'auth_caller')]:
    dump(fp, label, depth=1)

print('dump-auth2: %d functions -> %s' % (len(seen), OUT))
