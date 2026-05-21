# Locate vtables by scanning memory for the typeinfo pointers we found.
#
# From string-walk we have typeinfo struct addresses for each class:
#   Stick3CryptDmxUniverse   @ 0x100970dc8
#   Stick5CryptDmxUniverse   @ 0x1009843c0
#   DasNetCryptDmxUniverse   @ 0x100986688
#   AesOStream               @ 0x100851c50
#   AesIStream               @ 0x100851ae0
#   AesOStreamBuffer         @ 0x100851c68
#   AesIStreamBuffer         @ 0x100851af8
#   DasEccAesCryptography    @ 0x100851ee0
#   DasDhRsaCryptography<1024> @ 0x100ae7e20
#   DasDhRsaCryptography<512>  @ 0x100b12398
#   DasEccStreamCryptography @ 0x100852088
#   DasCryptography          @ 0x100851d50
#
# An Itanium-ABI vtable is laid out:
#     -0x10  offset_to_top
#     -0x08  typeinfo_ptr    ← this is the typeinfo struct address
#     +0x00  vt_slot[0]      ← what objects' vptr points at
#     +0x08  vt_slot[1]
#     ...
#
# So scanning memory for an 8-byte little-endian value equal to a typeinfo
# address finds the typeinfo_ptr field of every vtable for that class
# (primary + secondary base vtables). Vtable[0] = that_address + 8.
#
# Then dump every fn pointer at vt_slot[N] for N in [0..32) until 0/non-code.

# @category Stick

import os, re, struct
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from java.lang import Long

OUT_DIR = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out5')
try:
    os.makedirs(OUT_DIR)
except OSError:
    pass

prog = currentProgram
fm = prog.getFunctionManager()
mem = prog.getMemory()
af = prog.getAddressFactory()
monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
decomp.openProgram(prog)


def addr(a):
    return af.getDefaultAddressSpace().getAddress(a)


def get_ptr(a):
    try:
        return mem.getLong(a) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        return None


def find_le_qword(value):
    """Return all addresses where the 8-byte LE encoding of `value` occurs."""
    pat = struct.pack('<Q', value)
    hits = []
    a = mem.findBytes(prog.getMinAddress(), pat, None, True, monitor)
    while a is not None and len(hits) < 200:
        hits.append(a)
        try:
            a = mem.findBytes(a.add(1), pat, None, True, monitor)
        except Exception:
            break
    return hits


def dump_function(func, out):
    out.write('==== %s @ %s ====\n' % (func.getName(True), func.getEntryPoint()))
    out.write('signature: %s\n' % func.getPrototypeString(True, True))
    out.write('size: %d body bytes\n' % func.getBody().getNumAddresses())
    callees = sorted(set('%s @ %s' % (f.getName(True), f.getEntryPoint())
                         for f in func.getCalledFunctions(monitor)))
    out.write('\n-- callees (%d) --\n' % len(callees))
    for c in callees:
        out.write('  ' + c + '\n')
    callers = sorted(set('%s @ %s' % (f.getName(True), f.getEntryPoint())
                         for f in func.getCallingFunctions(monitor)))
    out.write('\n-- callers (%d) --\n' % len(callers))
    for c in callers:
        out.write('  ' + c + '\n')
    out.write('\n-- decompilation --\n')
    res = decomp.decompileFunction(func, 180, monitor)
    if res.decompileCompleted():
        out.write(res.getDecompiledFunction().getC())
    else:
        out.write('(decompilation failed: %s)\n' % res.getErrorMessage())
    out.write('\n')


# (class_label, typeinfo_addr)
TARGETS = [
    ('Stick3CryptDmxUniverse',     0x100970dc8),
    ('Stick5CryptDmxUniverse',     0x1009843c0),
    ('DasNetCryptDmxUniverse',     0x100986688),
    ('AesOStream',                 0x100851c50),
    ('AesIStream',                 0x100851ae0),
    ('AesOStreamBuffer',           0x100851c68),
    ('AesIStreamBuffer',           0x100851af8),
    ('DasEccAesCryptography',      0x100851ee0),
    ('DasDhRsaCryptography_1024',  0x100ae7e20),
    ('DasDhRsaCryptography_512',   0x100b12398),
    ('DasEccStreamCryptography',   0x100852088),
    ('DasCryptography',            0x100851d50),
]

summary = open(os.path.join(OUT_DIR, 'SUMMARY.txt'), 'w')
summary.write('Vtable hunt by typeinfo-ptr search — ESA2 HardwareManager\n\n')

seen_funcs = set()

for label, ti_addr in TARGETS:
    summary.write('\n#### %s   typeinfo @ 0x%x\n' % (label, ti_addr))
    occurrences = find_le_qword(ti_addr)
    summary.write('  typeinfo_ptr field occurs %d time(s)\n' % len(occurrences))
    for occ in occurrences:
        # occ = address of the typeinfo_ptr field in the vtable.
        # vt_slot[0] is at occ + 8.
        summary.write('    typeinfo_ptr @ %s   ->  vtable slot[0] @ 0x%x\n' %
                      (occ, int(occ.getOffset()) + 8))
        base = int(occ.getOffset()) + 8
        # Walk up to 32 slots
        for slot in range(0, 32):
            sa = addr(base + slot * 8)
            fp = get_ptr(sa)
            if fp is None:
                summary.write('      vt[%2d] @ 0x%x  <unmapped>\n' %
                              (slot, base + slot * 8))
                break
            # End-of-vtable: many ABIs put zeros or a new offset-to-top
            if fp == 0:
                summary.write('      vt[%2d] @ 0x%x  = 0  (end?)\n' %
                              (slot, base + slot * 8))
                break
            fa = addr(fp)
            f = fm.getFunctionAt(fa) or fm.getFunctionContaining(fa)
            if f is None:
                # Could be a pure-virtual stub or non-code; stop
                summary.write('      vt[%2d] @ 0x%x  -> 0x%x (no fn)\n' %
                              (slot, base + slot * 8, fp))
                break
            summary.write('      vt[%2d] @ 0x%x  -> %s @ %s  (size %d)\n' %
                          (slot, base + slot * 8, f.getName(True),
                           f.getEntryPoint(), f.getBody().getNumAddresses()))
            if f.getEntryPoint() in seen_funcs:
                continue
            seen_funcs.add(f.getEntryPoint())
            safe_fn = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
            path = os.path.join(OUT_DIR, '%s_vt%02d_%s_%s.txt' %
                                (label, slot, f.getEntryPoint(), safe_fn))
            with open(path, 'w') as o:
                dump_function(f, o)

summary.write('\n=== total functions dumped: %d ===\n' % len(seen_funcs))
summary.close()
print('find-vtables: dumped %d functions to %s' % (len(seen_funcs), OUT_DIR))
