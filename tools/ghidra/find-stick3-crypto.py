# Locate XHL_Stick3CryptDmxUniverse + related crypto vtables and dump methods.
#
# Now that we know the real class names (with XHL_ prefix and namespaces):
#   XHL_Stick3ANet::XHL_Stick3CryptDmxUniverse        ← DE3 DMX cipher class
#   XHL_DasNetCryptDmxUniverse                        ← base class
#   XHL_AesOStream / XHL_AesIStream                   ← block cipher streams
#   XHL_AesOStreamBuffer / XHL_AesIStreamBuffer       ← buffered variants
#   XHL_DasDhRsaCryptography<1024>/<512>              ← DH+RSA handshake
#   XHL_DasEccAesCryptography                         ← ECC+AES
#   XHL_DasEccStreamCryptography
#   XHL_DasCryptography(KeySize)
#
# We dump the full method table of each, plus every called function — that
# walks us into the actual AES inlining and the per-session key derivation.

# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT_DIR = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out3')
try:
    os.makedirs(OUT_DIR)
except OSError:
    pass

prog = currentProgram
fm   = prog.getFunctionManager()
st   = prog.getSymbolTable()
af   = prog.getAddressFactory()
mem  = prog.getMemory()
ref_mgr = prog.getReferenceManager()
monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
decomp.openProgram(prog)

# Substrings to match in mangled or demangled symbol names
KEYWORDS = [
    'Stick3CryptDmxUniverse',
    'Stick5CryptDmxUniverse',
    'DasNetCryptDmxUniverse',
    'AesOStream',
    'AesIStream',
    'DasDhRsaCryptography',
    'DasEccAesCryptography',
    'DasEccStreamCryptography',
    'DasCryptography',
    # Also: any function whose source-file string contains these
    'XHL_Stick3',
    'XHL_DasNet',
]


def addr(a):
    return af.getDefaultAddressSpace().getAddress(a)


def get_ptr(a):
    try:
        return mem.getLong(a) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        return None


def dump_function_full(func, out, depth=0):
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


# Find all symbols (any) whose name contains any keyword.
all_hits = []  # list of (kw, symbol)
for sym in st.getAllSymbols(False):
    n = sym.getName(True)
    for kw in KEYWORDS:
        if kw in n:
            all_hits.append((kw, sym))
            break

summary_path = os.path.join(OUT_DIR, 'SUMMARY.txt')
out_summary = open(summary_path, 'w')
out_summary.write('Stick3 crypto search — ESA2 HardwareManager (2024-03-21)\n\n')

# Bucket by kind
funcs = []          # symbols that are functions
vtables = []        # vtable symbols (__ZTV)
typeinfos = []      # __ZTI
typenames = []      # __ZTS
others = []
for kw, sym in all_hits:
    n = sym.getName(False) or ''
    nfull = sym.getName(True)
    if fm.getFunctionAt(sym.getAddress()):
        funcs.append(sym)
    elif n.startswith('__ZTV') or 'vtable' in nfull:
        vtables.append(sym)
    elif n.startswith('__ZTI') or 'typeinfo' in nfull and 'name' not in nfull:
        typeinfos.append(sym)
    elif n.startswith('__ZTS') or 'typeinfo-name' in nfull:
        typenames.append(sym)
    else:
        others.append(sym)

out_summary.write('=== Summary counts ===\n')
out_summary.write('  functions:      %d\n' % len(funcs))
out_summary.write('  vtables:        %d\n' % len(vtables))
out_summary.write('  typeinfos:      %d\n' % len(typeinfos))
out_summary.write('  type-names:     %d\n' % len(typenames))
out_summary.write('  other:          %d\n\n' % len(others))

out_summary.write('=== Functions (named methods) ===\n')
for s in sorted(funcs, key=lambda s: s.getAddress()):
    out_summary.write('  %s @ %s\n' % (s.getName(True), s.getAddress()))

out_summary.write('\n=== Vtables ===\n')
for s in sorted(vtables, key=lambda s: s.getAddress()):
    out_summary.write('  %s @ %s\n' % (s.getName(True), s.getAddress()))

out_summary.write('\n=== Typeinfos ===\n')
for s in sorted(typeinfos, key=lambda s: s.getAddress()):
    out_summary.write('  %s @ %s\n' % (s.getName(True), s.getAddress()))

out_summary.write('\n=== Type-name strings ===\n')
for s in sorted(typenames, key=lambda s: s.getAddress()):
    out_summary.write('  %s @ %s\n' % (s.getName(True), s.getAddress()))

# Walk every vtable: dump fn-pointer slots and full decomp of each
seen = set()
out_summary.write('\n\n=== Vtable layouts ===\n')
for s in sorted(vtables, key=lambda s: s.getAddress()):
    name = s.getName(True)
    a = s.getAddress()
    out_summary.write('\n--- %s @ %s ---\n' % (name, a))
    base = int(a.getOffset())
    for slot in range(0, 32):
        slot_off = 0x10 + slot * 8  # skip offset-to-top + typeinfo
        slot_addr = addr(base + slot_off)
        fp = get_ptr(slot_addr)
        if fp is None or fp == 0:
            break
        # Heuristic to stop at end of vtable: if the qword is itself another
        # vtable symbol's address or clearly not code, bail.
        fa = addr(fp)
        f = fm.getFunctionAt(fa) or fm.getFunctionContaining(fa)
        if f is None:
            out_summary.write('  +0x%02x: 0x%x  (no fn)\n' % (slot_off, fp))
            continue
        out_summary.write('  +0x%02x: %s @ %s\n' %
                          (slot_off, f.getName(True), f.getEntryPoint()))
        if f.getEntryPoint() in seen:
            continue
        seen.add(f.getEntryPoint())
        safe_cls = re.sub(r'[^A-Za-z0-9._-]', '_', name)[:80]
        safe_fn  = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
        path = os.path.join(OUT_DIR, '%s_+%02x_%s.txt' % (safe_cls, slot_off, safe_fn))
        with open(path, 'w') as o:
            dump_function_full(f, o)

# Also dump every named function we matched directly
for s in sorted(funcs, key=lambda s: s.getAddress()):
    f = fm.getFunctionAt(s.getAddress())
    if f is None or f.getEntryPoint() in seen:
        continue
    seen.add(f.getEntryPoint())
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:140]
    path = os.path.join(OUT_DIR, 'fn_%s_%s.txt' % (f.getEntryPoint(), safe))
    with open(path, 'w') as o:
        dump_function_full(f, o)

out_summary.close()
print('find-stick3-crypto: dumped %d functions to %s' % (len(seen), OUT_DIR))
print('find-stick3-crypto: summary at %s' % summary_path)
