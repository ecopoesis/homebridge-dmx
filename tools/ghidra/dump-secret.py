# Decompile the 33-byte-secret deobfuscator + locate its obfuscated source,
# and find the initializer that populates the P-256 curve constants.
# @category Stick

import os, struct
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT_DIR = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out-secret')
try: os.makedirs(OUT_DIR)
except OSError: pass

prog = currentProgram
fm = prog.getFunctionManager()
af = prog.getAddressFactory()
mem = prog.getMemory()
rm = prog.getReferenceManager()
monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
decomp.openProgram(prog)
def addr(a): return af.getDefaultAddressSpace().getAddress(a)

def rd(a, n):
    buf = bytearray(n)
    try:
        mem.getBytes(addr(a), buf); return bytes(buf)
    except Exception:
        return None

def decompile(func):
    res = decomp.decompileFunction(func, 240, monitor)
    if res.decompileCompleted():
        return res.getDecompiledFunction().getC()
    return '(decompile failed: %s)\n' % res.getErrorMessage()

out = open(os.path.join(OUT_DIR, 'REPORT.txt'), 'w')

# memory blocks
out.write('=== MEMORY BLOCKS ===\n')
for b in mem.getBlocks():
    out.write('  %-20s %s - %s  init=%s  %s\n' %
              (b.getName(), b.getStart(), b.getEnd(),
               b.isInitialized(), 'rwx'[0] if b.isRead() else '-'))

# deobfuscators + network exchange + state getter
out.write('\n=== DEOBFUSCATORS / NETWORK / STATE ===\n')
for fp, label in [(0x100180E90, 'vt38_deobf_180E90'),
                  (0x100180D40, 'deobf_180D40'),
                  (0x1001C0650, 'vt20_net_exchange_1C0650'),
                  (0x1001C0A50, 'vt28_state_getter_1C0A50'),
                  (0x1001C0CF0, 'vt30_1C0CF0'),
                  (0x1004029b0, 'EC_decomp_rhs_4029b0')]:
    f = fm.getFunctionAt(addr(fp)) or fm.getFunctionContaining(addr(fp))
    if f is None:
        out.write('%s: no fn\n' % label); continue
    out.write('\n---- %s : %s @ %s ----\n' % (label, f.getName(True), f.getEntryPoint()))
    out.write(decompile(f))

# hunt the obfuscated 33-byte source: scan __const for plausible region,
# and read candidate addresses
out.write('\n=== CANDIDATE OBFUSCATED-SECRET BYTES ===\n')
for a in [0x1007b0490, 0x1007b04a0, 0x1007af9c0, 0x1007c0240, 0x1007c0250]:
    b = rd(a, 0x21)
    out.write('  0x%x : %s\n' % (a, b.hex() if b else '(unreadable)'))

# references to curve-constant addresses -> find the initializer
out.write('\n=== XREFS TO CURVE CONSTANTS ===\n')
for ca, label in [(0x100cf5bf0, 'prime_p'), (0x100cf5c10, 'order_n'),
                   (0x100cf5c30, 'generator_G'), (0x100cf8d11, 'decoded_secret')]:
    out.write('\n-- %s @ 0x%x --\n' % (label, ca))
    refs = rm.getReferencesTo(addr(ca))
    cnt = 0
    for r in refs:
        cnt += 1
        if cnt > 30:
            out.write('  ... (more)\n'); break
        fa = r.getFromAddress()
        f = fm.getFunctionContaining(fa)
        out.write('  %s  %s  from %s\n' %
                  (r.getReferenceType(), fa,
                   (f.getName(True) + ' @ ' + str(f.getEntryPoint())) if f else '(no fn)'))

out.close()
print('dump-secret: done -> %s' % OUT_DIR)
