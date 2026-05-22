# Decompile the X25519 -> AES-256-key KDF call chain.
# Chain (lldb Path D, ESA2 file addrs):
#   on_listWidgetDevice_itemSelectionChanged
#    -> 0x1005e1bd6 -> 0x1005e267b -> 0x1001780d1
#    -> 0x10010780e -> 0x1003f57c6  (key installer)
# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT_DIR = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out-kdf')
try: os.makedirs(OUT_DIR)
except OSError: pass

prog = currentProgram
fm = prog.getFunctionManager()
af = prog.getAddressFactory()
monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
decomp.openProgram(prog)
def addr(a): return af.getDefaultAddressSpace().getAddress(a)

def func_for(a):
    ad = addr(a)
    return fm.getFunctionAt(ad) or fm.getFunctionContaining(ad)

def decompile(func):
    res = decomp.decompileFunction(func, 240, monitor)
    if res.decompileCompleted():
        return res.getDecompiledFunction().getC()
    return '(decompilation failed: %s)\n' % res.getErrorMessage()

def dump(func, out, with_decomp=True):
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
    if with_decomp:
        out.write('\n-- decompilation --\n')
        out.write(decompile(func))
    out.write('\n')

# Chain call sites -> the function each address sits inside.
CHAIN = [
    ('callsite_1005e1bd6', 0x1005e1bd6),
    ('callsite_1005e267b', 0x1005e267b),
    ('kdf_outer_1001780d1', 0x1001780d1),
    ('kdf_1001780d1_fn',   0x1001780d1),
    ('kdf_inner_10010780e', 0x10010780e),
    ('key_installer_1003f57c6', 0x1003f57c6),
]

summary = open(os.path.join(OUT_DIR, 'SUMMARY.txt'), 'w')
seen = set()

# 1. Dump every function in the chain.
chain_funcs = []
for label, a in CHAIN:
    f = func_for(a)
    if f is None:
        summary.write('  %-26s 0x%x  (NO FUNCTION)\n' % (label, a))
        continue
    ep = f.getEntryPoint()
    summary.write('  %-26s 0x%x -> %s @ %s  size=%d callees=%d\n' %
                  (label, a, f.getName(True), ep,
                   f.getBody().getNumAddresses(),
                   len(set(f.getCalledFunctions(monitor)))))
    if str(ep) in seen:
        continue
    seen.add(str(ep))
    chain_funcs.append((label, f))
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:80]
    with open(os.path.join(OUT_DIR, '1_%s_%s.txt' % (label, safe)), 'w') as o:
        dump(f, o)

# 2. Decompile every direct callee of the two KDF-critical functions, so the
#    actual hash/curve arithmetic is visible.
KDF_CRITICAL = [0x1001780d1, 0x10010780e]
callee_seen = set(seen)
for a in KDF_CRITICAL:
    f = func_for(a)
    if f is None: continue
    for callee in sorted(f.getCalledFunctions(monitor), key=lambda x: str(x.getEntryPoint())):
        ep = str(callee.getEntryPoint())
        if ep in callee_seen: continue
        callee_seen.add(ep)
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', callee.getName(True))[:80]
        with open(os.path.join(OUT_DIR, '2_callee_%s_%s.txt' %
                                (callee.getEntryPoint(), safe)), 'w') as o:
            dump(callee, o)
        summary.write('    callee %s @ %s size=%d\n' %
                      (callee.getName(True), callee.getEntryPoint(),
                       callee.getBody().getNumAddresses()))

summary.write('\n=== chain funcs: %d, callees dumped: %d ===\n' %
              (len(chain_funcs), len(callee_seen) - len(seen)))
summary.close()
print('dump-kdf-chain: done -> %s' % OUT_DIR)
