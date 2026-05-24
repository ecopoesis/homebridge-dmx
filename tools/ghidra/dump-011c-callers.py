# Dump the call chain around FUN_1001bbca0 (the 0x011c reply handler):
#   - its 2 callers (FUN_1001bbc50, FUN_1001bc350) - see how param_3=0x00ec is set
#     and what they DO with the 236-byte plaintext
#   - FUN_1003f5740 (AES key install), FUN_1003f68e0 (AES-CBC decrypt)
#   - FUN_1001ee4d0 (build_msg used here), FUN_1001f2c80 (register pending reply)
#   - find the Stick3 device's vtable[+0xe8] function (the AES key getter)
#
# Also: dump the cross-refs to vt[+0xe8] = slot at offset 0xe8 (i.e. slot 29)
# for the Stick3 device class vtables.
#
# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out-011c-callers')
try: os.makedirs(OUT)
except OSError: pass

prog = currentProgram
fm = prog.getFunctionManager()
af = prog.getAddressFactory()
mem = prog.getMemory()
listing = prog.getListing()
monitor = ConsoleTaskMonitor()
decomp = DecompInterface(); decomp.openProgram(prog)
def addr(a): return af.getDefaultAddressSpace().getAddress(a)

def decompile(f):
    r = decomp.decompileFunction(f, 240, monitor)
    return r.getDecompiledFunction().getC() if r.decompileCompleted() else '(decompile failed)\n'

def dump_fn(ep, label):
    a = addr(ep)
    f = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
    if not f:
        with open(os.path.join(OUT, '%s_%x.txt' % (label, ep)), 'w') as o:
            o.write('NO FUNCTION at 0x%x\n' % ep)
        return None
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:80]
    fname = os.path.join(OUT, '%s_%s_%s.txt' % (label, f.getEntryPoint(), safe))
    with open(fname, 'w') as o:
        o.write('==== %s @ %s (%d bytes) ====\n' %
                (f.getName(True), f.getEntryPoint(), f.getBody().getNumAddresses()))
        callees = sorted(set('%s @ %s' % (c.getName(True), c.getEntryPoint())
                             for c in f.getCalledFunctions(monitor)))
        callers = sorted(set('%s @ %s' % (c.getName(True), c.getEntryPoint())
                             for c in f.getCallingFunctions(monitor)))
        o.write('-- callees (%d) --\n  ' % len(callees) + '\n  '.join(callees) + '\n')
        o.write('\n-- callers (%d) --\n  ' % len(callers) + '\n  '.join(callers) + '\n\n')
        o.write('-- decompilation --\n')
        o.write(decompile(f))
    return f

TARGETS = [
    (0x1001bbc50, 'caller1'),       # caller of FUN_1001bbca0
    (0x1001bc350, 'caller2'),       # caller of FUN_1001bbca0
    (0x1001bbca0, 'handler_011c'),  # FUN_1001bbca0 itself, for reference
    (0x1003f5740, 'aes_key_install'),
    (0x1003f68e0, 'aes_cbc_decrypt'),
    (0x1003f4530, 'aes_cfb_key_install'),
    (0x1001ee4d0, 'build_msg'),
    (0x1001f2c80, 'register_pending'),
    (0x100195b20, 'get_reply_buf'),
    (0x100195ec0, 'wait_reply'),
    (0x1001b0df0, 'get_socket'),
]

print('dumping handler-related functions ...')
for ep, label in TARGETS:
    dump_fn(ep, label)

# Hunt the vtable+0xe8 entry. We look at the existing Stick3-class typeinfo
# pointers (from memory note) and try to identify the primary vtable.
# Stick3ANet typeinfo @ 0x100970160 -- vtable for Stick3ANet is at
# typeinfo - sizeof(some Itanium ABI overhead). Easier: find every place
# in code where ".vt[0xe8]" is loaded then called for that device, and
# dump those callees.
print('finding vtable[+0xe8] load sites ...')
ec_callsites = []
instr_iter = listing.getInstructions(True)
while instr_iter.hasNext():
    ins = instr_iter.next()
    # Pattern: "mov rax, [r?+0xe8]" followed shortly by "call rax".
    # In Ghidra, easiest is to look at the mnemonic + scalar.
    if ins.getMnemonicString() not in ('MOV', 'CALL', 'JMP'):
        continue
    for i in range(ins.getNumOperands()):
        for o in ins.getOpObjects(i):
            try:
                v = o.getValue() if hasattr(o, 'getValue') else None
            except Exception:
                v = None
            if v == 0xe8:
                ec_callsites.append((str(ins.getAddress()), ins.toString()))
print('e8 displacement sites: %d' % len(ec_callsites))

with open(os.path.join(OUT, 'vt_e8_sites.txt'), 'w') as o:
    o.write('=== instructions with 0xe8 as a scalar operand ===\n')
    for a, t in ec_callsites:
        f = fm.getFunctionContaining(addr(int(a, 16)))
        fn = f.getName(True) if f else '?'
        o.write('  %s  %s  in %s\n' % (a, t, fn))

# Dump FUN_1001bbca0's caller of vt[+0xe8] specifically.
# Use the bytes pattern: search the binary for instruction sequences
# that look like "callq [reg+0xe8]" -- in x86-64 that's FF 90 e8 00 00 00
# or FF 50 + sign-extended -- "FF 90 E8 00 00 00".
print('searching for byte pattern FF 90 E8 00 00 00 (call [reg+0xe8]) ...')
pattern = bytes([0xff, 0x90, 0xe8, 0x00, 0x00, 0x00])
mem_blocks = [b for b in mem.getBlocks() if b.isInitialized() and b.isExecute()]
hits = []
for block in mem_blocks:
    start = block.getStart().getOffset()
    end = block.getEnd().getOffset()
    size = end - start + 1
    if size > 64*1024*1024: continue
    buf = bytearray(size)
    try:
        block.getBytes(block.getStart(), buf)
    except Exception:
        continue
    i = 0
    while True:
        idx = buf.find(pattern, i)
        if idx == -1: break
        hits.append(start + idx)
        i = idx + 1
print('found %d call-via-[reg+0xe8] sites' % len(hits))

with open(os.path.join(OUT, 'vt_e8_calls.txt'), 'w') as o:
    o.write('=== call [reg+0xe8] sites (FF 90 E8 00 00 00) ===\n')
    for h in hits:
        a = addr(h)
        f = fm.getFunctionContaining(a)
        fn = f.getName(True) if f else '?'
        o.write('  0x%x  in %s\n' % (h, fn))

print('dump-011c-callers: done -> %s' % OUT)
