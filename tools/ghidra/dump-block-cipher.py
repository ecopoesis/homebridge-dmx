# Dump the actual block cipher (AES?) under CBC and CFB modes.

# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT_DIR = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out16')
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
    res = decomp.decompileFunction(func, 360, monitor)
    if res.decompileCompleted():
        out.write(res.getDecompiledFunction().getC())
    else:
        out.write('(decompilation failed: %s)\n' % res.getErrorMessage())
    out.write('\n')


ROOTS = {
    'CFB_block_FUN_1003f4690':  0x1003f4690,
    'CBC_block_FUN_1003f5980':  0x1003f5980,
    'CFB_helper_FUN_1003f4660': 0x1003f4660,
    'preencrypt_FUN_100107a30': 0x100107a30,
}

seen = set()
summary = open(os.path.join(OUT_DIR, 'SUMMARY.txt'), 'w')

for label, fp in ROOTS.items():
    f = fm.getFunctionAt(addr(fp)) or fm.getFunctionContaining(addr(fp))
    if f is None:
        summary.write('  %s 0x%x  (no fn)\n' % (label, fp))
        continue
    summary.write('  %-30s = %s @ %s  size=%d  callees=%d\n' %
                  (label, f.getName(True), f.getEntryPoint(),
                   f.getBody().getNumAddresses(),
                   len(set(f.getCalledFunctions(monitor)))))
    if f.getEntryPoint() in seen: continue
    seen.add(f.getEntryPoint())
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
    with open(os.path.join(OUT_DIR, '%s_%s_%s.txt' %
                            (label, f.getEntryPoint(), safe)), 'w') as o:
        dump(f, o)

# Walk into each block cipher to depth 1
for fp in (0x1003f4690, 0x1003f5980):
    f = fm.getFunctionAt(addr(fp))
    if f is None: continue
    summary.write('\n=== depth-1 callees of 0x%x ===\n' % fp)
    for c in sorted(f.getCalledFunctions(monitor), key=lambda f: f.getEntryPoint()):
        summary.write('  %s @ %s (size %d)\n' %
                      (c.getName(True), c.getEntryPoint(),
                       c.getBody().getNumAddresses()))
        if c.getEntryPoint() in seen: continue
        seen.add(c.getEntryPoint())
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', c.getName(True))[:120]
        with open(os.path.join(OUT_DIR, 'depth1_0x%x_%s_%s.txt' %
                                (fp, c.getEntryPoint(), safe)), 'w') as o:
            dump(c, o)

summary.write('\n=== total: %d ===\n' % len(seen))
summary.close()
print('dump-block-cipher: %d functions dumped to %s' % (len(seen), OUT_DIR))
