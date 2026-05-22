# Decompile HmSoftwareProfile::HmSoftwareProfile (+ its callees) — the
# constructor that hardcodes the software name + the auth key used as the
# HMAC-SHA256 key for the 0x48 handshake.
# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out-profile')
try: os.makedirs(OUT)
except OSError: pass

prog = currentProgram
fm = prog.getFunctionManager()
st = prog.getSymbolTable()
monitor = ConsoleTaskMonitor()
decomp = DecompInterface(); decomp.openProgram(prog)

def decompile(f):
    r = decomp.decompileFunction(f, 240, monitor)
    return r.getDecompiledFunction().getC() if r.decompileCompleted() else '(fail)\n'

seen = set()
def dump(f, tag, depth=0):
    if f is None or str(f.getEntryPoint()) in seen: return
    seen.add(str(f.getEntryPoint()))
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:70]
    cs = sorted(set(f.getCalledFunctions(monitor)), key=lambda x: str(x.getEntryPoint()))
    with open(os.path.join(OUT, '%s_%s_%s.txt' % (tag, f.getEntryPoint(), safe)), 'w') as o:
        o.write('==== %s @ %s (%d bytes) ====\n' %
                (f.getName(True), f.getEntryPoint(), f.getBody().getNumAddresses()))
        o.write('callees: ' + ', '.join(str(c.getEntryPoint()) for c in cs) + '\n\n')
        o.write(decompile(f))
    if depth > 0:
        for c in cs:
            nm = c.getName(True)
            if nm.startswith('_') or 'std::' in nm or 'operator' in nm or 'QArray' in nm \
               or 'QString' in nm or 'QDir' in nm: continue
            dump(c, tag + '_c', depth - 1)

summary = open(os.path.join(OUT, 'SUMMARY.txt'), 'w')

# find any symbol mentioning HmSoftwareProfile
hits = []
for s in st.getAllSymbols(True):
    n = s.getName(True)
    if 'HmSoftwareProfile' in n or 'SoftwareProfile' in n:
        hits.append((n, s.getAddress()))
summary.write('=== HmSoftwareProfile symbols ===\n')
for n, a in hits[:40]:
    summary.write('  %s @ %s\n' % (n, a))
    f = fm.getFunctionContaining(a)
    if f and ('HmSoftwareProfile' in f.getName(True)):
        dump(f, 'profile', depth=2)

summary.write('\n=== dumped %d ===\n' % len(seen))
summary.close()
print('dump-profile: %d functions, %d symbol hits -> %s' % (len(seen), len(hits), OUT))
