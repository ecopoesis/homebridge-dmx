# Dump every Stick3CryptDmxUniverse vtable slot function + every caller of
# XHL_UdpSocket::send. Finds the actual DMX encrypt routine.
#
# Vtable sites (from dyld_info -fixups, typeinfo @ 0x100970DC0):
#   Primary:    0x100962BE0  (slot[0] @ +0x08, primary virtuals)
#   Sub1:       0x100962CC0  (5 methods, secondary base #1)
#   Sub2:       0x100962CE8  (5 methods, secondary base #2)
#   Sub3:       0x100962D28  (5 methods, secondary base #3)
#   Sub4:       0x100962D60  (5 methods, secondary base #4)
#   Sub5:       0x100962DA0  (last group, also has VTT entries)
#
# UdpSocket sends are FUN_100677060 (sendUnicast?) and FUN_100677330
# (sendBroadcast or send-to-many?). 26 + 6 callers.

# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT_DIR = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out6')
try:
    os.makedirs(OUT_DIR)
except OSError:
    pass

prog = currentProgram
fm = prog.getFunctionManager()
af = prog.getAddressFactory()
mem = prog.getMemory()
ref_mgr = prog.getReferenceManager()
monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
decomp.openProgram(prog)


def addr(a):
    return af.getDefaultAddressSpace().getAddress(a)


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


# Hardcoded vtable slot function addresses extracted from dyld_info -fixups
VTABLE_SLOTS = {
    'Stick3CryptDmxUniverse_PRIMARY': [
        # primary @ 0x100962BE0; slot 0 is the byte just after typeinfo_ptr.
        # (Itanium: slot 0 typically = D0/D1 destructors, slots 2+ = virtuals.)
        (0, 0x1001818E0),
        (1, 0x100181A30),
        (2, 0x1001AA240),
        (3, 0x1005EF5D0),
        (4, 0x100181FC0),
        (5, 0x100181BB0),
        (6, 0x1001AA410),
        (7, 0x1005EF0E0),
        (8, 0x1005EF0F0),
        (9, 0x1005EF250),
        (10, 0x100181CB0),
        (11, 0x1005EF2A0),
        (12, 0x1001C0340),
        (13, 0x1005EF4A0),
        (14, 0x1001AA2B0),
        (15, 0x1001AA110),
        (16, 0x1005EF700),
        (17, 0x100181FB0),
        (18, 0x100334140),
        (19, 0x1005EF800),
        (20, 0x1005EF8F0),
        (21, 0x1003342B0),
        (22, 0x1001A9D50),
        (23, 0x100181BC0),
    ],
    'Stick3CryptDmxUniverse_SUB1_at_0x100962CC0': [
        (0, 0x1001A9F00),
        (1, 0x100181910),
        (2, 0x100181A60),
    ],
    'Stick3CryptDmxUniverse_SUB2_at_0x100962CE8': [
        (0, 0x100181CA0),
        (1, 0x100181940),
        (2, 0x100181AA0),
        (3, 0x1005F0510),
        (4, 0x1005F0520),
    ],
    'Stick3CryptDmxUniverse_SUB3_at_0x100962D28': [
        (0, 0x100181970),
        (1, 0x100181AE0),
        (2, 0x1001C0410),
        (3, 0x1001C0540),
        (4, 0x100421210),
    ],
    'Stick3CryptDmxUniverse_SUB4_at_0x100962D60': [
        (0, 0x1001819B0),
        (1, 0x100181B20),
        (2, 0x100334300),
    ],
    'Stick3CryptDmxUniverse_SUB5_at_0x100962DA0': [
        (0, 0x1001819F0),
        (1, 0x100181B60),
        (2, 0x10062E1A0),
        (3, 0x10062E2A0),
    ],
}

# UdpSocket send functions — every caller is a candidate
UDP_SEND_FNS = {
    'XHL_UdpSocket_sendA_FUN_100677060': 0x100677060,
    'XHL_UdpSocket_sendB_FUN_100677330': 0x100677330,
}

summary = open(os.path.join(OUT_DIR, 'SUMMARY.txt'), 'w')
summary.write('Stick3 vtable + UDP-send callers — ESA2 HardwareManager\n\n')

seen = set()

# --- Dump vtable slots ---
for label, slots in VTABLE_SLOTS.items():
    summary.write('\n=== %s ===\n' % label)
    for slot_idx, fp in slots:
        fa = addr(fp)
        f = fm.getFunctionAt(fa) or fm.getFunctionContaining(fa)
        if f is None:
            summary.write('  vt[%d] @ 0x%x  (no fn)\n' % (slot_idx, fp))
            continue
        summary.write('  vt[%d] @ 0x%x = %s @ %s (size %d)\n' %
                      (slot_idx, fp, f.getName(True),
                       f.getEntryPoint(), f.getBody().getNumAddresses()))
        if f.getEntryPoint() in seen:
            continue
        seen.add(f.getEntryPoint())
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
        path = os.path.join(OUT_DIR, '%s_vt%02d_%s_%s.txt' %
                            (label, slot_idx, f.getEntryPoint(), safe))
        with open(path, 'w') as o:
            dump_function(f, o)

# --- Dump every caller of UdpSocket::send ---
for label, fp in UDP_SEND_FNS.items():
    summary.write('\n=== Callers of %s @ 0x%x ===\n' % (label, fp))
    fn = fm.getFunctionAt(addr(fp))
    if fn is None:
        summary.write('  (function not found)\n')
        continue
    callers = sorted(set(f.getEntryPoint() for f in fn.getCallingFunctions(monitor)))
    for ep in callers:
        f = fm.getFunctionAt(ep)
        summary.write('  %s @ %s  (size %d)\n' %
                      (f.getName(True), f.getEntryPoint(),
                       f.getBody().getNumAddresses()))
        if f.getEntryPoint() in seen:
            continue
        seen.add(f.getEntryPoint())
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
        path = os.path.join(OUT_DIR, 'udpcaller_%s_%s.txt' %
                            (f.getEntryPoint(), safe))
        with open(path, 'w') as o:
            dump_function(f, o)

summary.write('\n=== total functions dumped: %d ===\n' % len(seen))
summary.close()
print('dump-stick3-vtable: dumped %d functions to %s' % (len(seen), OUT_DIR))
