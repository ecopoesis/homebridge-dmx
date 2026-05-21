# Locate the real DMX cipher path in the symbolized ESA2 HardwareManager.
#
# What we know from dump-anchors:
#   - DmxUniversePage::sendDmx (worker fn dispatched via QtConcurrent::run) calls
#         (*((**(this+0x48))[2]))((this+0x48)+0x10, this+0x58)
#     i.e. a virtual on an object held at DmxUniversePage::m_field_0x48,
#     passing the 488-byte raw DMX buffer at this+0x58.
#   - receiveDmx calls slot +0x18 of the same vtable.
#   - That object's class is one of the RTTI-anchored ones (CryptDmxUniverse,
#     AesOStream, ...) — only RTTI strings exist (no symbolized methods).
#
# Plan:
#   1. Find every RTTI typeinfo-name string that contains "CryptDmxUniverse"
#      or "AesOStream"/"AesIStream"/"Dmx" (broader net).
#   2. For each, walk xrefs back to the corresponding __ZTV* (vtable) — the
#      vtable is a sequence of function pointers and its 2nd qword points to
#      the typeinfo. So for each xref site that looks like a vtable, list the
#      function pointers at +0x10, +0x18, +0x20, +0x28 and dump those functions.
#   3. Also: cross-ref _sendto (0x1006ed9c6) callers — the encrypt+send fn
#      should appear among them. Dump every caller.
#   4. Print everything to tools/ghidra/out2/.

# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import RefType

OUT_DIR = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out2')
try:
    os.makedirs(OUT_DIR)
except OSError:
    pass

prog = currentProgram
fm   = prog.getFunctionManager()
st   = prog.getSymbolTable()
af   = prog.getAddressFactory()
mem  = prog.getMemory()
listing = prog.getListing()
ref_mgr = prog.getReferenceManager()
monitor = ConsoleTaskMonitor()

decomp = DecompInterface()
decomp.openProgram(prog)


def addr(a):
    return af.getDefaultAddressSpace().getAddress(a)


def get_ptr(a):
    """Read an 8-byte LE pointer from address a."""
    try:
        return mem.getLong(a) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        return None


def dump_function_brief(func, out):
    out.write('  FUNC %s @ %s  (size %d)\n' % (func.getName(True),
              func.getEntryPoint(), func.getBody().getNumAddresses()))


def dump_function_full(func, out):
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
    res = decomp.decompileFunction(func, 120, monitor)
    if res.decompileCompleted():
        out.write(res.getDecompiledFunction().getC())
    else:
        out.write('(decompilation failed: %s)\n' % res.getErrorMessage())
    out.write('\n')


# ---------------------------------------------------------------------------
# 1. Find RTTI typeinfo-name strings for DMX/Crypto classes
# ---------------------------------------------------------------------------
target_class_substrings = [
    'CryptDmxUniverse', 'AesOStream', 'AesIStream',
    'DasEccAesCryptography', 'DasDhRsaCryptography',
    'DasEccStreamCryptography', 'DasCryptography',
    'DmxUniverse',  # base class candidates
]

rtti_strings = []  # list of (substring, name, address)
for sym in st.getAllSymbols(False):
    name = sym.getName(True)
    if '__ZTS' in name or 'typeinfo-name' in name:
        for sub in target_class_substrings:
            if sub in name:
                rtti_strings.append((sub, name, sym.getAddress()))
                break
    elif '__ZTI' in name or 'typeinfo' in name:
        for sub in target_class_substrings:
            if sub in name:
                rtti_strings.append((sub, name, sym.getAddress()))
                break
    elif '__ZTV' in name or 'vtable' in name:
        for sub in target_class_substrings:
            if sub in name:
                rtti_strings.append((sub, name, sym.getAddress()))
                break

# ---------------------------------------------------------------------------
# 2. Dump summary, vtable layouts, and full decomps of every vtable slot fn
# ---------------------------------------------------------------------------
summary_path = os.path.join(OUT_DIR, 'SUMMARY.txt')
seen_funcs = set()
out_summary = open(summary_path, 'w')
out_summary.write('Cipher-anchor search — ESA2 HardwareManager (2024-03-21)\n\n')

out_summary.write('=== RTTI/vtable symbols for DMX/Crypto classes ===\n')
for sub, name, a in rtti_strings:
    out_summary.write('  [%s] %s @ %s\n' % (sub, name, a))
out_summary.write('\n')

# For every vtable symbol (__ZTV*), the layout is:
#     [+0x00] offset-to-top (signed 64)
#     [+0x08] typeinfo pointer
#     [+0x10] virtual fn 0
#     [+0x18] virtual fn 1
#     [+0x20] virtual fn 2
#     ...
# We saw sendDmx do ((vt+0x10))(...)  — that's the *second function pointer*
# in the vtable structure if you measure from the typeinfo pointer; actually
# *((vptr)[2])(...) at C-source level. In the Ghidra decomp it's the value
# obtained as **((vptr+0x10) cast to ptr-to-ptr), which means vtable[+0x10]
# IS the first function-pointer slot (Itanium ABI: vptr points at the first
# fn slot, NOT the typeinfo header). So:
#     - The address Ghidra calls "vtable @ X" is the START of the structure
#       (offset-to-top); typical layout above.
#     - "vptr" stored in objects = X + 0x10
#     - vt[0] = mem[X+0x10],  vt[1] = mem[X+0x18], ...
# We dump fn pointers at offsets +0x10 through +0x80 (16 slots) of any vtable.

vtable_syms = [(s, n, a) for (s, n, a) in rtti_strings if '__ZTV' in n or 'vtable' in n]
out_summary.write('=== Vtable layouts (first 16 fn slots) ===\n')
for sub, name, a in vtable_syms:
    out_summary.write('\n--- %s @ %s ---\n' % (name, a))
    base = int(a.getOffset())
    # Skip first two qwords (offset-to-top, typeinfo); slots start at +0x10
    for slot in range(0, 16):
        slot_addr = addr(base + 0x10 + slot * 8)
        fp = get_ptr(slot_addr)
        if fp is None:
            out_summary.write('  +0x%02x: <unmapped>\n' % (0x10 + slot * 8))
            continue
        if fp == 0:
            out_summary.write('  +0x%02x: NULL — stop\n' % (0x10 + slot * 8))
            break
        fa = addr(fp)
        f = fm.getFunctionAt(fa) or fm.getFunctionContaining(fa)
        if f is None:
            out_summary.write('  +0x%02x: 0x%x  (no function)\n' %
                              (0x10 + slot * 8, fp))
            continue
        out_summary.write('  +0x%02x: %s @ %s\n' %
                          (0x10 + slot * 8, f.getName(True), f.getEntryPoint()))
        if f.getEntryPoint() in seen_funcs:
            continue
        seen_funcs.add(f.getEntryPoint())
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
        path = os.path.join(OUT_DIR, 'vt_%s_+%02x_%s.txt' %
                            (re.sub(r'[^A-Za-z0-9._-]', '_', name)[:60],
                             0x10 + slot * 8, safe))
        with open(path, 'w') as o:
            dump_function_full(f, o)

# ---------------------------------------------------------------------------
# 3. Cross-reference _sendto callers — the encrypt+send fn must be among them
# ---------------------------------------------------------------------------
out_summary.write('\n=== Callers of _sendto (0x1006ed9c6) ===\n')
sendto_addr = addr(0x1006ed9c6)
sendto_fn = fm.getFunctionAt(sendto_addr)
sendto_callers = set()
if sendto_fn is not None:
    for ref in ref_mgr.getReferencesTo(sendto_addr):
        from_addr = ref.getFromAddress()
        caller = fm.getFunctionContaining(from_addr)
        if caller is not None:
            sendto_callers.add(caller.getEntryPoint())

for ep in sorted(sendto_callers):
    f = fm.getFunctionAt(ep)
    out_summary.write('  %s @ %s\n' % (f.getName(True), f.getEntryPoint()))
    if ep in seen_funcs:
        continue
    seen_funcs.add(ep)
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
    path = os.path.join(OUT_DIR, 'sendto_caller_%s_%s.txt' % (f.getEntryPoint(), safe))
    with open(path, 'w') as o:
        dump_function_full(f, o)

out_summary.close()
print('find-cipher: dumped %d functions to %s' % (len(seen_funcs), OUT_DIR))
print('find-cipher: summary at %s' % summary_path)
