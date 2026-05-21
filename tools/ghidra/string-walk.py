# Find crypto/cipher code via string xrefs.
#
# Ghidra didn't auto-create RTTI symbols for XHL_Stick3CryptDmxUniverse etc.,
# but the binary clearly contains:
#   - typeinfo-name strings like "26XHL_DasNetCryptDmxUniverse"
#     "N14XHL_Stick3ANet26XHL_Stick3CryptDmxUniverseE"
#   - leaked source paths "../source/common/.../XHL_DasNetCryptDmxUniverse.cpp"
#   - method-name strings in error logs like
#     "[XHL_DasNetCryptDmxUniverse::setIoMode] pSubscribeUdpPort failed"
#
# Strategy: for each interesting string, locate its bytes in memory and find
# every function that references it. That function IS the method whose name
# the string mentions (since the string is its diagnostic log message), or
# AT LEAST a function in the crypto path.

# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressSet
from ghidra.program.model.listing import CodeUnit

OUT_DIR = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out4')
try:
    os.makedirs(OUT_DIR)
except OSError:
    pass

prog = currentProgram
fm = prog.getFunctionManager()
mem = prog.getMemory()
listing = prog.getListing()
ref_mgr = prog.getReferenceManager()
monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
decomp.openProgram(prog)


def find_string_addrs(needle):
    """Return all addresses in memory where the literal bytes of `needle`
    occur (followed by a NUL byte for safety)."""
    pattern = needle.encode('utf-8') + b'\x00'
    hits = []
    # Use Memory.findBytes
    addr = mem.findBytes(prog.getMinAddress(), pattern, None, True, monitor)
    while addr is not None and len(hits) < 50:
        hits.append(addr)
        nxt = addr.add(1)
        try:
            addr = mem.findBytes(nxt, pattern, None, True, monitor)
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


# (needle, suggested filename slug)
NEEDLES = [
    # Source file paths leak class boundaries
    ('XHL_DasNetCryptDmxUniverse.cpp',          'XHL_DasNetCryptDmxUniverse_cpp'),
    ('XHL_DasEccAesCryptography.cpp',           'XHL_DasEccAesCryptography_cpp'),
    ('XHL_DasEccStreamCryptography.cpp',        'XHL_DasEccStreamCryptography_cpp'),
    ('XHL_DasDhRsaCryptography.hpp',            'XHL_DasDhRsaCryptography_hpp'),

    # Error/debug strings that contain method names
    ('XHL_DasNetCryptDmxUniverse::setIoMode',   'setIoMode'),

    # RTTI strings — anything that references them is the typeinfo struct
    # for that class, and the vtable points at it.
    ('N14XHL_Stick3ANet26XHL_Stick3CryptDmxUniverseE',  'Stick3CryptDmxUniverse_rtti'),
    ('N14XHL_Stick5ANet26XHL_Stick5CryptDmxUniverseE',  'Stick5CryptDmxUniverse_rtti'),
    ('26XHL_DasNetCryptDmxUniverse',                     'DasNetCryptDmxUniverse_rtti'),
    ('14XHL_AesOStream',                                  'AesOStream_rtti'),
    ('14XHL_AesIStream',                                  'AesIStream_rtti'),
    ('20XHL_AesOStreamBuffer',                            'AesOStreamBuffer_rtti'),
    ('20XHL_AesIStreamBuffer',                            'AesIStreamBuffer_rtti'),
    ('25XHL_DasEccAesCryptography',                       'DasEccAesCryptography_rtti'),
    ('24XHL_DasDhRsaCryptographyILj1024EE',               'DasDhRsaCryptography_1024_rtti'),
    ('24XHL_DasDhRsaCryptographyILj512EE',                'DasDhRsaCryptography_512_rtti'),
    ('28XHL_DasEccStreamCryptography',                    'DasEccStreamCryptography_rtti'),
    ('19XHL_DasCryptography',                             'DasCryptography_rtti'),
]

summary = open(os.path.join(OUT_DIR, 'SUMMARY.txt'), 'w')
summary.write('String-walk anchors — ESA2 HardwareManager (2024-03-21)\n\n')

seen_funcs = set()

for needle, slug in NEEDLES:
    summary.write('\n#### needle: %r\n' % needle)
    str_addrs = find_string_addrs(needle)
    summary.write('  found %d occurrence(s) of string\n' % len(str_addrs))
    if not str_addrs:
        continue

    for str_addr in str_addrs:
        summary.write('    @ %s\n' % str_addr)

        # Walk one ref-hop: who references this string?
        L1_refs = list(ref_mgr.getReferencesTo(str_addr))
        L1_funcs = set()
        L1_data_addrs = set()
        for r in L1_refs:
            fa = r.getFromAddress()
            f = fm.getFunctionContaining(fa)
            if f is not None:
                L1_funcs.add(f.getEntryPoint())
            else:
                L1_data_addrs.add(fa)

        summary.write('      direct fn refs: %d\n' % len(L1_funcs))
        for ep in sorted(L1_funcs):
            f = fm.getFunctionAt(ep)
            summary.write('        %s @ %s\n' % (f.getName(True), f.getEntryPoint()))

        summary.write('      direct data refs: %d\n' % len(L1_data_addrs))
        for da in sorted(L1_data_addrs):
            summary.write('        data @ %s\n' % da)
            # Walk one more hop: who references THAT data location?
            L2_refs = list(ref_mgr.getReferencesTo(da))
            for r2 in L2_refs:
                fa2 = r2.getFromAddress()
                f2 = fm.getFunctionContaining(fa2)
                if f2 is not None:
                    L1_funcs.add(f2.getEntryPoint())
                    summary.write('          via %s -> fn %s @ %s\n' %
                                  (da, f2.getName(True), f2.getEntryPoint()))
                else:
                    # Could be the vtable structure itself
                    summary.write('          via %s -> data @ %s\n' % (da, fa2))
                    # And one more hop (vtable -> referencing fn)
                    for r3 in ref_mgr.getReferencesTo(fa2):
                        fa3 = r3.getFromAddress()
                        f3 = fm.getFunctionContaining(fa3)
                        if f3 is not None:
                            L1_funcs.add(f3.getEntryPoint())
                            summary.write('            via %s -> fn %s @ %s\n' %
                                          (fa2, f3.getName(True),
                                           f3.getEntryPoint()))

        # Dump every collected function
        for ep in sorted(L1_funcs):
            if ep in seen_funcs:
                continue
            seen_funcs.add(ep)
            f = fm.getFunctionAt(ep)
            if f is None:
                continue
            safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:140]
            path = os.path.join(OUT_DIR, '%s_%s_%s.txt' %
                                (slug, f.getEntryPoint(), safe))
            with open(path, 'w') as o:
                dump_function(f, o)

summary.write('\n=== total functions dumped: %d ===\n' % len(seen_funcs))
summary.close()
print('string-walk: dumped %d functions to %s' % (len(seen_funcs), OUT_DIR))
