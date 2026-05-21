# Dump everything around the SHA-1 KDF candidate to confirm role.

# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT_DIR = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out19')
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


ROOTS = {
    'sha1_init_FUN_100407940':       0x100407940,   # 39B — should be a tiny init
    'sha1_update_FUN_100407970':     0x100407970,   # update
    'sha1_final_FUN_100407a60':      0x100407a60,   # 615B
    'kdf_candidate_FUN_10065aad0':   0x10065aad0,   # KDF candidate using sha1 + salt
    'dest_FUN_1006420d0':            0x1006420d0,   # what kdf writes via
    'getter_FUN_1006aebb0':          0x1006aebb0,   # what supplies KDF input
    'kdf_caller_FUN_10065ac20':      0x10065ac20,
    'kdf_caller_FUN_10065d160':      0x10065d160,
}

seen = set()
summary = open(os.path.join(OUT_DIR, 'SUMMARY.txt'), 'w')

for label, fp in ROOTS.items():
    f = fm.getFunctionAt(addr(fp)) or fm.getFunctionContaining(addr(fp))
    if f is None:
        summary.write('  %s 0x%x  (no fn)\n' % (label, fp)); continue
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

summary.write('\n=== total: %d ===\n' % len(seen))
summary.close()
print('dump-kdf-context: %d functions dumped to %s' % (len(seen), OUT_DIR))
