# Decompile HWM's XHL_DasNetDevice::authenticate() and the LSAG_ALL handshake
# builder (LSAG_ALL is inline in code at 0x1001f233b). This is the 0x47/0x48
# TCP-auth handshake our send_dmx is failing (0x48 reply status 100 vs 0).
# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out-auth')
try: os.makedirs(OUT)
except OSError: pass

prog = currentProgram
fm = prog.getFunctionManager()
af = prog.getAddressFactory()
rm = prog.getReferenceManager()
monitor = ConsoleTaskMonitor()
decomp = DecompInterface(); decomp.openProgram(prog)
def addr(a): return af.getDefaultAddressSpace().getAddress(a)

def decompile(f):
    r = decomp.decompileFunction(f, 240, monitor)
    return r.getDecompiledFunction().getC() if r.decompileCompleted() else '(decompile failed)\n'

seen = set()
summary = open(os.path.join(OUT, 'SUMMARY.txt'), 'w')

def dump(f, tag, with_callees=False):
    if f is None: return
    ep = str(f.getEntryPoint())
    if ep in seen: return
    seen.add(ep)
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:70]
    callees = sorted(set(f.getCalledFunctions(monitor)),
                     key=lambda x: str(x.getEntryPoint()))
    with open(os.path.join(OUT, '%s_%s_%s.txt' % (tag, ep, safe)), 'w') as o:
        o.write('==== %s @ %s (%d bytes) ====\n' %
                (f.getName(True), ep, f.getBody().getNumAddresses()))
        o.write('callees:\n')
        for c in callees:
            o.write('  %s @ %s\n' % (c.getName(True), c.getEntryPoint()))
        o.write('\ncallers:\n')
        for c in sorted(set(f.getCallingFunctions(monitor)), key=lambda x: str(x.getEntryPoint())):
            o.write('  %s @ %s\n' % (c.getName(True), c.getEntryPoint()))
        o.write('\n' + decompile(f))
    summary.write('  %s : %s @ %s  (%d callees)\n' % (tag, f.getName(True), ep, len(callees)))
    if with_callees:
        for c in callees:
            nm = c.getName(True)
            if nm.startswith('_') or 'std::' in nm or 'operator' in nm: continue
            dump(c, tag + '_callee', False)

# 1. the LSAG_ALL builder — function containing the inline "LSAG_ALL" bytes
f = fm.getFunctionContaining(addr(0x1001f233b))
summary.write('=== LSAG_ALL inline @ 0x1001f233b ===\n')
dump(f, '1_lsag_builder', with_callees=True)

# 2. XHL_DasNetDevice::authenticate() — xref the assert string at 0x1007ffeef
summary.write('\n=== authenticate() (string xref 0x1007ffeef) ===\n')
for r in rm.getReferencesTo(addr(0x1007ffeef)):
    dump(fm.getFunctionContaining(r.getFromAddress()), '2_authenticate', with_callees=True)

# 3. "Configuring Capsens Security" string xref @ 0x1007b84b4
summary.write('\n=== Capsens Security (0x1007b84b4) ===\n')
for r in rm.getReferencesTo(addr(0x1007b84b4)):
    dump(fm.getFunctionContaining(r.getFromAddress()), '3_capsens', with_callees=True)

summary.write('\n=== total: %d ===\n' % len(seen))
summary.close()
print('dump-authenticate: %d functions -> %s' % (len(seen), OUT))
