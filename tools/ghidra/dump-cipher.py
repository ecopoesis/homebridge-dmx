# Dump the actual cipher function chain.
#
# From FUN_1001a9d50 (the "send DMX" virtual method):
#   FUN_1001eeac0 = builds 576-byte AES frame (the ENCRYPT function)
#   FUN_1001b0340 = XHL_UdpSocket::send (verify it routes to sendto)
#   FUN_100333f40 = sequence-number bookkeeping (param_1 -> &seqnum_out)
#   FUN_100333ae0 = pre-encrypt setup (maybe IV refresh)
#
# Also dump callers of FUN_1001eeac0 (the encrypt) and all its callees:
# AES tables and round logic live in there.

# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT_DIR = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out7')
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
    out.write('signature: %s\n' % func.getPrototypeString(True, True))
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

# Functions to dump (label -> address)
ROOTS = {
    'sendDmx_FUN_1001a9d50':       0x1001a9d50,  # outer; for context
    'encrypt_FUN_1001eeac0':       0x1001eeac0,  # THE ENCRYPT FUNCTION
    'udpsend_FUN_1001b0340':       0x1001b0340,  # UDP send wrapper
    'pre_FUN_100333ae0':           0x100333ae0,
    'getseqno_FUN_100333f40':      0x100333f40,
    'getip_FUN_1001b1780':         0x1001b1780,  # gets IP from socket?
    'unknown_FUN_1006a70a0':       0x1006a70a0,  # ??? (mutex variant)
    'unknown_FUN_1006a6f70':       0x1006a6f70,  # ??? (mutex variant)
    'unknown_FUN_10060b8e0':       0x10060b8e0,  # mutex lock?
    'unknown_FUN_10060b980':       0x10060b980,  # mutex unlock?
}

# Also: recursively descend into encrypt to depth 1 — its callees are the
# round logic / sbox lookups.
ENCRYPT_ADDR = 0x1001eeac0

seen = set()
summary = open(os.path.join(OUT_DIR, 'SUMMARY.txt'), 'w')
summary.write('Cipher dump — chain rooted at FUN_1001a9d50\n\n')

for label, fp in ROOTS.items():
    f = fm.getFunctionAt(addr(fp)) or fm.getFunctionContaining(addr(fp))
    if f is None:
        summary.write('  %s 0x%x  (no function)\n' % (label, fp))
        continue
    summary.write('  %s = %s @ %s (size %d, callees=%d)\n' %
                  (label, f.getName(True), f.getEntryPoint(),
                   f.getBody().getNumAddresses(),
                   len(set(f.getCalledFunctions(monitor)))))
    if f.getEntryPoint() in seen: continue
    seen.add(f.getEntryPoint())
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
    with open(os.path.join(OUT_DIR, '%s_%s_%s.txt' %
                            (label, f.getEntryPoint(), safe)), 'w') as o:
        dump(f, o)

# Descend into encrypt fn's callees (depth 1)
enc = fm.getFunctionAt(addr(ENCRYPT_ADDR))
if enc:
    summary.write('\n=== encrypt fn callees (depth 1) ===\n')
    for c in sorted(enc.getCalledFunctions(monitor), key=lambda f: f.getEntryPoint()):
        summary.write('  callee: %s @ %s (size %d)\n' %
                      (c.getName(True), c.getEntryPoint(),
                       c.getBody().getNumAddresses()))
        if c.getEntryPoint() in seen: continue
        seen.add(c.getEntryPoint())
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', c.getName(True))[:120]
        with open(os.path.join(OUT_DIR, 'enccallee_%s_%s.txt' %
                                (c.getEntryPoint(), safe)), 'w') as o:
            dump(c, o)

summary.write('\n=== total dumped: %d ===\n' % len(seen))
summary.close()
print('dump-cipher: %d functions dumped to %s' % (len(seen), OUT_DIR))
