# Find XHL_XHardwareLibrary::setSoftware() and its caller — the caller passes
# the hardcoded software-code / software-name / software-KEY. That key is the
# HMAC-SHA256 key for the 0x48 auth handshake. Also decompile the hash init
# (FUN_100408420) to confirm the hash algorithm.
# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out-sw')
try: os.makedirs(OUT)
except OSError: pass

prog = currentProgram
fm = prog.getFunctionManager()
af = prog.getAddressFactory()
rm = prog.getReferenceManager()
mem = prog.getMemory()
monitor = ConsoleTaskMonitor()
decomp = DecompInterface(); decomp.openProgram(prog)
def addr(a): return af.getDefaultAddressSpace().getAddress(a)

def decompile(f):
    r = decomp.decompileFunction(f, 240, monitor)
    return r.getDecompiledFunction().getC() if r.decompileCompleted() else '(fail)\n'

seen = set()
def dump(f, tag, callers=False):
    if f is None or str(f.getEntryPoint()) in seen: return
    seen.add(str(f.getEntryPoint()))
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:60]
    with open(os.path.join(OUT, '%s_%s_%s.txt' % (tag, f.getEntryPoint(), safe)), 'w') as o:
        o.write('==== %s @ %s (%d bytes) ====\n' %
                (f.getName(True), f.getEntryPoint(), f.getBody().getNumAddresses()))
        cs = sorted(set(f.getCalledFunctions(monitor)), key=lambda x: str(x.getEntryPoint()))
        o.write('callees: ' + ', '.join(str(c.getEntryPoint()) for c in cs) + '\n\n')
        o.write(decompile(f))
    if callers:
        for c in sorted(set(f.getCallingFunctions(monitor)), key=lambda x: str(x.getEntryPoint())):
            dump(c, tag + '_caller', False)

summary = open(os.path.join(OUT, 'SUMMARY.txt'), 'w')

# 1. setSoftware — xref the __PRETTY_FUNCTION__ string at 0x10081a947
summary.write('=== setSoftware (xref 0x10081a947) ===\n')
for r in rm.getReferencesTo(addr(0x10081a947)):
    f = fm.getFunctionContaining(r.getFromAddress())
    if f:
        summary.write('  setSoftware = %s @ %s\n' % (f.getName(True), f.getEntryPoint()))
        dump(f, '1_setSoftware', callers=True)

# 2. the hash init/update/final used by the HMAC
summary.write('\n=== HMAC hash primitives ===\n')
for fp, t in [(0x100408420, '2_hash_init'), (0x10040aee0, '2_hash_update'),
              (0x10040afb0, '2_hash_final'), (0x10040b290, '2_hash_oneshot')]:
    f = fm.getFunctionAt(addr(fp))
    if f: dump(f, t, False)

# 3. also dump bytes around the "software" cstring region for nearby key data
summary.write('\n=== done, %d fns ===\n' % len(seen))
summary.close()
print('dump-setsoftware: %d functions -> %s' % (len(seen), OUT))
