# Walk the constructor chain to find where the 8-word cipher state is
# initialized.  Top-level: FUN_100178f10 (Stick3CryptDmxUniverse::ctor)
# delegates the heavy lifting to FUN_1001a9a00 (base-class ctor).
#
# Targets:
#   FUN_1001a9a00   base constructor (sets up sub-objects incl. cipher)
#   FUN_100178bb0   caller of Stick3 ctor (one level UP — who creates these?)
#   FUN_100105770   AesOStream constructor
#   the s_XHL_Stick3ANet... string is at 0x1007ff054 — dump bytes too

# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT_DIR = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out10')
try: os.makedirs(OUT_DIR)
except OSError: pass

prog = currentProgram
fm = prog.getFunctionManager()
af = prog.getAddressFactory()
mem = prog.getMemory()
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


ROOTS = {
    'base_ctor_FUN_1001a9a00':           0x1001a9a00,
    'caller_of_Stick3_ctor_100178bb0':   0x100178bb0,
    'AesOStream_ctor_100105770':         0x100105770,
}

seen = set()
summary = open(os.path.join(OUT_DIR, 'SUMMARY.txt'), 'w')

# Read and print the source-tag string at 0x1007ff054
summary.write('=== Source-tag string at 0x1007ff054 ===\n')
try:
    sb = []
    a = addr(0x1007ff054)
    for i in range(120):
        b = mem.getByte(a.add(i)) & 0xff
        if b == 0: break
        sb.append(chr(b))
    summary.write('  ' + repr(''.join(sb)) + '\n\n')
except Exception as e:
    summary.write('  (read failed: %s)\n' % e)

for label, fp in ROOTS.items():
    f = fm.getFunctionAt(addr(fp)) or fm.getFunctionContaining(addr(fp))
    if f is None:
        summary.write('  %s 0x%x  (no fn)\n' % (label, fp))
        continue
    summary.write('  %s = %s @ %s  size=%d\n' %
                  (label, f.getName(True), f.getEntryPoint(),
                   f.getBody().getNumAddresses()))
    if f.getEntryPoint() in seen: continue
    seen.add(f.getEntryPoint())
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
    with open(os.path.join(OUT_DIR, '%s_%s_%s.txt' %
                            (label, f.getEntryPoint(), safe)), 'w') as o:
        dump(f, o)

# Also descend one hop into base ctor
base_ctor = fm.getFunctionAt(addr(0x1001a9a00))
if base_ctor:
    summary.write('\n=== base ctor depth-1 callees ===\n')
    for c in sorted(base_ctor.getCalledFunctions(monitor), key=lambda f: f.getEntryPoint()):
        summary.write('  callee: %s @ %s (size %d)\n' %
                      (c.getName(True), c.getEntryPoint(),
                       c.getBody().getNumAddresses()))
        if c.getEntryPoint() in seen: continue
        seen.add(c.getEntryPoint())
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', c.getName(True))[:120]
        with open(os.path.join(OUT_DIR, 'basector_d1_%s_%s.txt' %
                                (c.getEntryPoint(), safe)), 'w') as o:
            dump(c, o)

summary.write('\n=== total dumped: %d ===\n' % len(seen))
summary.close()
print('dump-ctor-chain: %d functions dumped to %s' % (len(seen), OUT_DIR))
