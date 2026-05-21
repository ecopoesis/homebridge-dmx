# Dump all candidate AES encrypt method addresses + walk one hop deep into
# the most-promising primary candidate (DasEccStreamCryptography vt[3] @
# 0x100108200) so we see the actual AES round logic / S-box.
#
# Vtables under inspection:
#   AesOStream primary @ vptr 0x100851B20: vt[0]=0x100105900, vt[1]=0x1001059B0
#   AesOStream secondary @ vptr 0x100851B48: vt[0]=0x100105950, vt[1]=0x100105A10
#   DasEccStreamCryptography primary @ vptr 0x100851F38:
#     vt[0]=0x100107BA0, vt[1]=0x100107BD0, vt[2]=0x100106290, vt[3]=0x100108200

# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT_DIR = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out8')
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


CANDIDATES = {
    'AesOStream_primary_vt0':       0x100105900,
    'AesOStream_primary_vt1':       0x1001059B0,
    'AesOStream_secondary_vt0':     0x100105950,
    'AesOStream_secondary_vt1':     0x100105A10,
    'DasEccStreamCrypto_vt0':       0x100107BA0,
    'DasEccStreamCrypto_vt1':       0x100107BD0,
    'DasEccStreamCrypto_vt2':       0x100106290,
    'DasEccStreamCrypto_vt3_ENC?':  0x100108200,
}

seen = set()
summary = open(os.path.join(OUT_DIR, 'SUMMARY.txt'), 'w')

for label, fp in CANDIDATES.items():
    f = fm.getFunctionAt(addr(fp)) or fm.getFunctionContaining(addr(fp))
    if f is None:
        summary.write('  %s 0x%x  (no fn)\n' % (label, fp))
        continue
    summary.write('  %-32s = %s @ %s  size=%d  callees=%d\n' %
                  (label, f.getName(True), f.getEntryPoint(),
                   f.getBody().getNumAddresses(),
                   len(set(f.getCalledFunctions(monitor)))))
    if f.getEntryPoint() in seen: continue
    seen.add(f.getEntryPoint())
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
    with open(os.path.join(OUT_DIR, '%s_%s_%s.txt' %
                            (label, f.getEntryPoint(), safe)), 'w') as o:
        dump(f, o)

# Walk one deeper into the candidate encrypt (DasEccStreamCrypto vt[3])
candidate_enc = fm.getFunctionAt(addr(0x100108200))
if candidate_enc:
    summary.write('\n=== depth-1 callees of DasEccStreamCrypto vt[3] (candidate ENCRYPT) ===\n')
    for c in sorted(candidate_enc.getCalledFunctions(monitor), key=lambda f: f.getEntryPoint()):
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
print('dump-aes-candidates: %d functions dumped to %s' % (len(seen), OUT_DIR))
