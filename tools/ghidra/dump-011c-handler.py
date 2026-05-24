# Find HWM's opcode-0x011c receive-handler + the 0x011 (go-live) precondition
# check.
#
# Strategy: scan every instruction for immediate operands matching the
# interesting constants and group by containing function:
#   * 0x011c (= 284) -- the opcode we send + the reply length, almost
#     certainly appears in HWM as a switch-case or `cmp r, 0x11c`.
#   * 0x00ec (= 236) -- a 2-byte marker inside the 0x011c reply's
#     258-byte payload at relative offset +0x12. A parser that examines
#     the payload will compare against this constant.
#   * 0x011  (= 17)  -- the go-live opcode. Very common immediate, so we
#     ONLY take hits whose containing function ALSO references 0x011c or
#     a Stick3 magic string, to filter false positives.
#
# Output goes to out-011c/.
#
# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out-011c')
try: os.makedirs(OUT)
except OSError: pass

prog = currentProgram
fm = prog.getFunctionManager()
af = prog.getAddressFactory()
mem = prog.getMemory()
listing = prog.getListing()
rm = prog.getReferenceManager()
monitor = ConsoleTaskMonitor()
decomp = DecompInterface(); decomp.openProgram(prog)

def decompile(f):
    r = decomp.decompileFunction(f, 240, monitor)
    return r.getDecompiledFunction().getC() if r.decompileCompleted() else '(decompile failed)\n'

def safe_name(f):
    return re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:80]

# ---------------------------------------------------------------------------
# 1. Walk every instruction once; collect operand scalars we care about.
# ---------------------------------------------------------------------------
TARGETS = {0x011c, 0x00ec, 0x0011, 0x0010, 0x000f}
hits = {v: {} for v in TARGETS}   # value -> { func_entry -> [addrs] }

print('scanning instructions ...')
total = 0
instr_iter = listing.getInstructions(True)
while instr_iter.hasNext():
    ins = instr_iter.next()
    total += 1
    for i in range(ins.getNumOperands()):
        objs = ins.getOpObjects(i)
        for o in objs:
            try:
                v = o.getValue() if hasattr(o, 'getValue') else None
            except Exception:
                v = None
            if v in TARGETS:
                f = fm.getFunctionContaining(ins.getAddress())
                if f is None: continue
                ep = str(f.getEntryPoint())
                hits[v].setdefault(ep, []).append(str(ins.getAddress()))
print('scanned %d instructions' % total)

# ---------------------------------------------------------------------------
# 2. Identify "interesting" functions: any function that references 0x011c
#    OR 0x00ec is a prime candidate (these constants are rare). 0x10/0x11/0xf
#    are kept only if the SAME function also references 0x011c or 0x00ec.
# ---------------------------------------------------------------------------
prime = set(hits[0x011c].keys()) | set(hits[0x00ec].keys())

# ---------------------------------------------------------------------------
# 3. Also xref the Stick magic strings -- so we capture the network-receive
#    dispatch even if it doesn't use 0x011c as a literal.
# ---------------------------------------------------------------------------
magic_xrefs = set()
needles = ['Stick_3A', 'LSAG_ALL', 'Stick_U1', 'Siudi_7B']
for d in listing.getDefinedData(True):
    try:
        if not d.hasStringValue(): continue
        s = str(d.getValue())
    except Exception:
        continue
    if s not in needles: continue
    for r in rm.getReferencesTo(d.getAddress()):
        f = fm.getFunctionContaining(r.getFromAddress())
        if f: magic_xrefs.add(str(f.getEntryPoint()))

# ---------------------------------------------------------------------------
# 4. Dump.
# ---------------------------------------------------------------------------
summary = open(os.path.join(OUT, 'SUMMARY.txt'), 'w')
summary.write('=== immediate-operand hit counts ===\n')
for v in sorted(TARGETS):
    summary.write('  0x%04x : %d functions, %d sites\n' %
                  (v, len(hits[v]), sum(len(x) for x in hits[v].values())))
summary.write('  magic-string xref funcs: %d\n' % len(magic_xrefs))
summary.write('\n=== functions referencing 0x011c ===\n')
for ep in sorted(hits[0x011c].keys()):
    f = fm.getFunctionAt(af.getDefaultAddressSpace().getAddress(int(ep, 16)))
    if not f: continue
    summary.write('  %s  %s  sites=%d  size=%d  also_0xec=%s  magic_xref=%s\n' % (
        ep, f.getName(True), len(hits[0x011c][ep]),
        f.getBody().getNumAddresses(),
        'Y' if ep in hits[0x00ec] else 'n',
        'Y' if ep in magic_xrefs else 'n'))

summary.write('\n=== functions referencing 0x00ec ===\n')
for ep in sorted(hits[0x00ec].keys()):
    f = fm.getFunctionAt(af.getDefaultAddressSpace().getAddress(int(ep, 16)))
    if not f: continue
    summary.write('  %s  %s  sites=%d  size=%d  also_0x11c=%s  magic_xref=%s\n' % (
        ep, f.getName(True), len(hits[0x00ec][ep]),
        f.getBody().getNumAddresses(),
        'Y' if ep in hits[0x011c] else 'n',
        'Y' if ep in magic_xrefs else 'n'))

# Anchor list: every prime func, plus magic-xref funcs that also touch 0x11
# (those are the network-dispatch loops).
dump_set = set(prime)
for ep in magic_xrefs:
    if ep in hits[0x0011] or ep in hits[0x0010] or ep in hits[0x000f]:
        dump_set.add(ep)

summary.write('\n=== dumping %d candidate functions ===\n' % len(dump_set))
for ep in sorted(dump_set):
    addr = af.getDefaultAddressSpace().getAddress(int(ep, 16))
    f = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
    if not f: continue
    name = safe_name(f)
    sites_11c = hits[0x011c].get(ep, [])
    sites_ec  = hits[0x00ec].get(ep, [])
    fname = os.path.join(OUT, 'fn_%s_%s.txt' % (ep, name))
    with open(fname, 'w') as o:
        o.write('==== %s @ %s (%d bytes) ====\n' %
                (f.getName(True), f.getEntryPoint(), f.getBody().getNumAddresses()))
        o.write('sites of 0x011c : %s\n' % ', '.join(sites_11c))
        o.write('sites of 0x00ec : %s\n' % ', '.join(sites_ec))
        o.write('sites of 0x0011 : %s\n' % ', '.join(hits[0x0011].get(ep, [])))
        o.write('sites of 0x0010 : %s\n' % ', '.join(hits[0x0010].get(ep, [])))
        o.write('sites of 0x000f : %s\n' % ', '.join(hits[0x000f].get(ep, [])))
        o.write('magic-string xref: %s\n' % ('YES' if ep in magic_xrefs else 'no'))
        callees = sorted(set('%s @ %s' % (c.getName(True), c.getEntryPoint())
                             for c in f.getCalledFunctions(monitor)))
        callers = sorted(set('%s @ %s' % (c.getName(True), c.getEntryPoint())
                             for c in f.getCallingFunctions(monitor)))
        o.write('\n-- callees (%d) --\n  ' % len(callees) + '\n  '.join(callees) + '\n')
        o.write('\n-- callers (%d) --\n  ' % len(callers) + '\n  '.join(callers) + '\n\n')
        o.write('-- decompilation --\n')
        o.write(decompile(f))
    summary.write('  dumped %s -> fn_%s_%s.txt\n' % (f.getName(True), ep, name))

summary.close()
print('dump-011c-handler: %d functions -> %s' % (len(dump_set), OUT))
