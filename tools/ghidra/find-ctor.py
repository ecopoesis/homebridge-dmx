# Locate the constructor(s) of XHL_Stick3CryptDmxUniverse and the
# DasEccStreamCryptography subobject it embeds.
#
# Method: in x86_64 PIC code, a constructor sets the object's vptr via
#   lea rax, [rip + delta]    ; rax = address of vt slot 0
#   mov [rdi], rax            ; obj->vptr = rax
# Ghidra creates a Reference of type DATA from the lea instruction's address
# to the vtable's slot-0 address.
#
# So xrefs to vptr values from CODE locations = constructor / VTT setup.
#
# Vptrs of interest (per our fixup mining):
#   Stick3CryptDmxUniverse  primary  vptr = 0x100962BE8  (= vt site + 8)
#   Stick3CryptDmxUniverse  sub1     vptr = 0x100962CC8
#   Stick3CryptDmxUniverse  sub2     vptr = 0x100962CF0
#   Stick3CryptDmxUniverse  sub3     vptr = 0x100962D30
#   Stick3CryptDmxUniverse  sub4     vptr = 0x100962D68
#   Stick3CryptDmxUniverse  sub5     vptr = 0x100962DA8
#   DasEccStreamCryptography vptr   = 0x100851F38
#   DasEccAesCryptography    vptr   = 0x100851D88
#   AesOStream               vptr   = 0x100851B20

# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT_DIR = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out9')
try: os.makedirs(OUT_DIR)
except OSError: pass

prog = currentProgram
fm = prog.getFunctionManager()
af = prog.getAddressFactory()
ref_mgr = prog.getReferenceManager()
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


VPTRS = {
    'Stick3_primary':           0x100962BE8,
    'Stick3_sub1':              0x100962CC8,
    'Stick3_sub2':              0x100962CF0,
    'Stick3_sub3':              0x100962D30,
    'Stick3_sub4':              0x100962D68,
    'Stick3_sub5':              0x100962DA8,
    'DasEccStreamCryptography': 0x100851F38,
    'DasEccAesCryptography':    0x100851D88,
    'AesOStream':               0x100851B20,
    'AesOStream_sec':           0x100851B48,
}

seen = set()
summary = open(os.path.join(OUT_DIR, 'SUMMARY.txt'), 'w')

for label, vptr in VPTRS.items():
    a = addr(vptr)
    summary.write('\n#### %s  vptr @ 0x%x\n' % (label, vptr))
    refs = list(ref_mgr.getReferencesTo(a))
    code_callers = set()
    for r in refs:
        fa = r.getFromAddress()
        f = fm.getFunctionContaining(fa)
        if f is not None:
            code_callers.add(f.getEntryPoint())
        else:
            summary.write('   data ref @ %s (no fn)\n' % fa)
    summary.write('   code refs from %d function(s):\n' % len(code_callers))
    for ep in sorted(code_callers):
        f = fm.getFunctionAt(ep)
        summary.write('     %s @ %s  (size %d)\n' %
                      (f.getName(True), f.getEntryPoint(),
                       f.getBody().getNumAddresses()))
        if f.getEntryPoint() in seen: continue
        seen.add(f.getEntryPoint())
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
        with open(os.path.join(OUT_DIR, '%s_%s_%s.txt' %
                                (label, f.getEntryPoint(), safe)), 'w') as o:
            dump(f, o)

summary.write('\n=== total dumped: %d ===\n' % len(seen))
summary.close()
print('find-ctor: %d functions dumped to %s' % (len(seen), OUT_DIR))
