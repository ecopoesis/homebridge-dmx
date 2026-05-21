# Ghidra headless post-script — dump the named anchor functions in the
# 2024-03-21 ESA2 HardwareManager so we can locate the real DMX cipher.
#
# This is Jython 2.7 (Ghidra script API). Run via analyzeHeadless:
#
#   $(brew --prefix)/share/ghidra/support/analyzeHeadless \
#       tools/ghidra HwmESA2 \
#       -import /Applications/ESA2/HardwareManager/HardwareManager.app/Contents/MacOS/HardwareManager \
#       -scriptPath tools/ghidra \
#       -postScript dump-anchors.py
#
# Output lands in tools/ghidra/out/.
#
# Anchors (from stick-aes-symbolized-breakthrough memory):
#   * DmxUniversePage::onTimerSendReceive  @ 0x100074090 (NOT live path)
#   * DmxWidget::onTimerSendAndReceive     (live path; posts QtConcurrent task)
#   * aes_encrypt_key128 / aes_encrypt / fcrypt_*  — Gladman (NOT DMX cipher)
#   * CryptDmxUniverse / AesOStream / AesIStream   — RTTI-only (no method names)
#   * DasEccAesCryptography / DasDhRsaCryptography / DasEccStreamCryptography
#
# Goal: for each named function, write its decompilation + callers/callees so
# we can walk:  DmxWidget::onTimerSendAndReceive -> QtConcurrent::run target
# -> custom AES encrypt -> sendto(2). Also note xrefs into the RTTI strings
# (CryptDmxUniverse etc.) — those reach the vtables; vtable entries are the
# method addresses even when symbol names are absent.

# @category Stick

import os, re

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT_DIR = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out')
try:
    os.makedirs(OUT_DIR)
except OSError:
    pass

# Symbols we want decompiled (substring match, case-sensitive).
WANTED_SUBSTRINGS = [
    # Live DMX path
    'onTimerSendAndReceive',
    'onTimerSendReceive',
    'sendDmx',
    'receiveDmx',
    # Qt async dispatch
    'QtConcurrent',
    # Known-not-DMX Gladman (sanity check + showfile/cloud crypto)
    'aes_encrypt_key128',
    'aes_encrypt_key',
    'aes_encrypt',
    'aes_decrypt',
    'fcrypt_init',
    'fcrypt_encrypt',
    'fcrypt_decrypt',
    # RTTI-anchored classes (likely only as data; we still report addresses)
    'CryptDmxUniverse',
    'AesOStream',
    'AesIStream',
    'DasEccAesCryptography',
    'DasDhRsaCryptography',
    'DasEccStreamCryptography',
    'DasCryptography',
    # libc sinks worth seeing callers of
    'sendto',
]

# Known explicit addresses (file vmaddr) to dump if symbol lookup misses them.
EXPLICIT_ADDRS = [
    0x100074090,  # DmxUniversePage::onTimerSendReceive (per memory)
    0x1006d2150,  # aes_encrypt_key128 (per memory)
    0x1006d2d30,  # aes_encrypt_key
    0x1006d0600,  # aes_encrypt
    0x1006d1380,  # aes_decrypt
    0x1006d4990,  # aes_init
    0x1006d49f0,  # fcrypt_init
    0x1006d4b10,  # fcrypt_encrypt
    0x1006d4c10,  # fcrypt_decrypt
]

prog = currentProgram
fm = prog.getFunctionManager()
st = prog.getSymbolTable()
af = prog.getAddressFactory()
listing = prog.getListing()
monitor = ConsoleTaskMonitor()

decomp = DecompInterface()
decomp.openProgram(prog)


def addr(a):
    return af.getDefaultAddressSpace().getAddress(a)


def dump_function(func, out):
    out.write('==== %s @ %s ====\n' % (func.getName(True), func.getEntryPoint()))
    out.write('signature: %s\n' % func.getPrototypeString(True, True))
    out.write('size: %d body bytes\n' % func.getBody().getNumAddresses())

    # Callees
    callees = sorted(set('%s @ %s' % (f.getName(True), f.getEntryPoint())
                         for f in func.getCalledFunctions(monitor)))
    out.write('\n-- callees (%d) --\n' % len(callees))
    for c in callees:
        out.write('  ' + c + '\n')

    # Callers
    callers = sorted(set('%s @ %s' % (f.getName(True), f.getEntryPoint())
                         for f in func.getCallingFunctions(monitor)))
    out.write('\n-- callers (%d) --\n' % len(callers))
    for c in callers:
        out.write('  ' + c + '\n')

    # Decompilation
    out.write('\n-- decompilation --\n')
    res = decomp.decompileFunction(func, 120, monitor)
    if res.decompileCompleted():
        out.write(res.getDecompiledFunction().getC())
    else:
        out.write('(decompilation failed: %s)\n' % res.getErrorMessage())
    out.write('\n')


def find_funcs_by_substring(subs):
    hits = {}
    # Walk all defined functions
    for f in fm.getFunctions(True):
        name = f.getName(True)  # includes namespace
        for s in subs:
            if s in name:
                hits.setdefault(s, []).append(f)
    # Also walk symbol table for non-function symbols (RTTI strings etc.)
    extra = []
    for sym in st.getAllSymbols(False):
        name = sym.getName(True)
        for s in subs:
            if s in name and not fm.getFunctionAt(sym.getAddress()):
                extra.append((s, sym))
    return hits, extra


hits, extras = find_funcs_by_substring(WANTED_SUBSTRINGS)

summary_path = os.path.join(OUT_DIR, 'SUMMARY.txt')
with open(summary_path, 'w') as summary:
    summary.write('Ghidra anchor dump for ESA2 HardwareManager (2024-03-21)\n')
    summary.write('Binary: %s\n\n' % prog.getExecutablePath())

    summary.write('=== Function hits by substring ===\n')
    for s in WANTED_SUBSTRINGS:
        funcs = hits.get(s, [])
        summary.write('%-32s %d function(s)\n' % (s, len(funcs)))
        for f in funcs:
            summary.write('    %s @ %s\n' % (f.getName(True), f.getEntryPoint()))
    summary.write('\n=== Non-function symbols (RTTI, data, etc.) ===\n')
    for s, sym in extras:
        summary.write('%-32s %s @ %s\n' % (s, sym.getName(True), sym.getAddress()))

# Dump each matched function to its own file
seen = set()
for s, funcs in hits.items():
    for f in funcs:
        ep = f.getEntryPoint()
        if ep in seen:
            continue
        seen.add(ep)
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
        path = os.path.join(OUT_DIR, '%s_%s.txt' % (ep, safe))
        with open(path, 'w') as out:
            dump_function(f, out)

# Also dump the explicit addresses (in case symbol lookup missed any)
for raw in EXPLICIT_ADDRS:
    a = addr(raw)
    f = fm.getFunctionAt(a)
    if f is None:
        f = fm.getFunctionContaining(a)
    if f is None:
        continue
    ep = f.getEntryPoint()
    if ep in seen:
        continue
    seen.add(ep)
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
    path = os.path.join(OUT_DIR, '%s_%s.txt' % (ep, safe))
    with open(path, 'w') as out:
        dump_function(f, out)

print('dump-anchors: %d functions dumped to %s' % (len(seen), OUT_DIR))
print('dump-anchors: summary at %s' % summary_path)
