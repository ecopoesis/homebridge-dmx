# Find + decompile HWM's LSAG_ALL / 0x47 / 0x48 TCP-auth handshake builder.
# Goal: learn what HWM puts in the 0x48 message — is the X25519 key a fresh
# ephemeral, or derived from a stored credential? That decides whether the
# auth is RE-able or needs "Security for Cloud Access" disabled.
# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out-handshake')
try: os.makedirs(OUT)
except OSError: pass

prog = currentProgram
fm = prog.getFunctionManager()
af = prog.getAddressFactory()
mem = prog.getMemory()
monitor = ConsoleTaskMonitor()
decomp = DecompInterface(); decomp.openProgram(prog)
listing = prog.getListing()

def decompile(f):
    r = decomp.decompileFunction(f, 240, monitor)
    return r.getDecompiledFunction().getC() if r.decompileCompleted() else '(fail)\n'

summary = open(os.path.join(OUT, 'SUMMARY.txt'), 'w')

# 1. find interesting strings
needles = ['LSAG_ALL', 'EccAesCryptography', 'DasNetEcc', 'Cloud', 'Security',
           'curve25519', 'Curve25519', '25519', 'softwareName', 'authenticat']
hits = {}
for d in listing.getDefinedData(True):
    v = d.getValue()
    s = None
    try:
        if d.hasStringValue(): s = str(v)
    except Exception:
        pass
    if not s: continue
    for n in needles:
        if n in s:
            hits.setdefault(n, []).append((d.getAddress(), s[:90]))

summary.write('=== string hits ===\n')
for n, lst in hits.items():
    for a, s in lst[:12]:
        summary.write('  [%s] %s : %r\n' % (n, a, s))

# 2. xref the LSAG_ALL / Ecc strings -> referencing functions -> decompile
seen = set()
def dump_fn(f, tag):
    ep = str(f.getEntryPoint())
    if ep in seen: return
    seen.add(ep)
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:70]
    with open(os.path.join(OUT, '%s_%s_%s.txt' % (tag, ep, safe)), 'w') as o:
        o.write('==== %s @ %s (%d bytes) ====\n' %
                (f.getName(True), ep, f.getBody().getNumAddresses()))
        callees = sorted(set('%s @ %s' % (c.getName(True), c.getEntryPoint())
                             for c in f.getCalledFunctions(monitor)))
        o.write('callees:\n  ' + '\n  '.join(callees) + '\n\n')
        o.write(decompile(f))
    summary.write('  dumped %s : %s @ %s\n' % (tag, f.getName(True), ep))

rm = prog.getReferenceManager()
summary.write('\n=== functions referencing handshake strings ===\n')
for n in ['LSAG_ALL', 'EccAesCryptography', 'DasNetEcc']:
    for a, s in hits.get(n, []):
        for r in rm.getReferencesTo(a):
            f = fm.getFunctionContaining(r.getFromAddress())
            if f: dump_fn(f, 'ref_' + n[:8])

summary.write('\n=== total dumped: %d ===\n' % len(seen))
summary.close()
print('dump-handshake: %d functions -> %s' % (len(seen), OUT))
