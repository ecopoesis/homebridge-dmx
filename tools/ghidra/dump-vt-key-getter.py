# Identify the vtable+0xe8 entry (AES-256 key getter) for the Stick3 device
# class, plus the sibling crypto functions FUN_1001bb3a0 and FUN_1001bb860
# which also use the same key path -- so we can correlate.
#
# Strategy: pyghidra has the binary indexed, so dump the function pointer
# in the device's __const vtable at slot +0xe8. Stick3ANet typeinfo at
# 0x100970160 -- vtable_top should be at typeinfo - 0x10 or via __const xref.
#
# Also: dump FUN_1001bb3a0 (sibling that also uses vt+0xe8 then aes_install)
# and FUN_1001bb860 (sibling crypto fn).
#
# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out-vt-key')
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
        return
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

# Sibling crypto functions also using AES key install.
SIBLINGS = [
    (0x1001bb3a0, 'sibling_bb3a0'),     # also calls FUN_1003f5740
    (0x1001bb860, 'sibling_bb860'),     # vt+0xe8 user
    (0x100353b20, 'sibling_353b20'),    # another decrypt user
    (0x100594ba0, 'sibling_594ba0'),
    (0x100595a40, 'sibling_595a40'),
    (0x1001bc0a0, 'unencrypted_011c'),  # the non-encrypted path -- shows what data layout the encrypted version equals
    (0x1001f89f0, 'register_pending'),  # used in handler
    (0x100195b20, 'extract_reply'),     # used in handler
]

for ep, label in SIBLINGS:
    dump_fn(ep, label)

# Find the function called at offset 0x1001bbee5 -- the indirect vt[+0xe8] call.
# Walk references FROM that instruction to find the resolved target (if Ghidra
# resolved it via dyld_info / objc / pointer-authentication). If not resolved,
# we'll have to find the device class vtable by another means.
ins_addr = addr(0x1001bbee5)
print('--- references at 0x1001bbee5 ---')
rm = prog.getReferenceManager()
for r in rm.getReferencesFrom(ins_addr):
    print('  ', r.getReferenceType(), r.getToAddress())

# Find Stick3ANet typeinfo @ 0x100970160 and the vtable preceding it.
ti_addr = addr(0x100970160)
print('\n--- references TO Stick3ANet typeinfo @ 0x100970160 ---')
for r in rm.getReferencesTo(ti_addr):
    print('  ', r.getFromAddress(), r.getReferenceType())

# Also dump the bytes around the typeinfo -- the vtable is just before it (in
# Itanium ABI, vtable layout = [offset-to-top][typeinfo*][vfn0][vfn1]...).
print('\n--- bytes near typeinfo 0x100970160 (vtable + typeinfo) ---')
buf = bytearray(0x800)
try:
    base = addr(0x10096fa00)
    mem.getBytes(base, buf)
    # interpret as 8-byte LE pointers; show first 256
    for i in range(0, len(buf), 8):
        v = int.from_bytes(buf[i:i+8], 'little')
        if 0x100000000 <= v < 0x110000000:
            print('  +0x%04x : 0x%016x' % (i, v))
except Exception as e:
    print('  err:', e)

# Search the entire binary's __DATA segments for any pointer = 0x100970160
# (typeinfo of Stick3ANet) -- the location 8 bytes BEFORE that hit is the
# vtable start; +0xe8 + 0x10 = slot.
print('\n--- searching for pointer 0x100970160 in __DATA ---')
target_bytes = (0x100970160).to_bytes(8, 'little')
for block in mem.getBlocks():
    if not block.isInitialized(): continue
    if block.isExecute(): continue        # data only
    start = block.getStart().getOffset()
    size = block.getSize()
    if size > 64*1024*1024: continue
    bb = bytearray(size)
    try:
        block.getBytes(block.getStart(), bb)
    except Exception:
        continue
    i = 0
    while True:
        idx = bb.find(target_bytes, i)
        if idx == -1: break
        ptr_addr = start + idx
        # In Itanium ABI, this offset = vtable + 0x8 (the typeinfo pointer slot).
        # So vtable starts at ptr_addr - 0x8 (the offset-to-top slot before it).
        # Slot index N is at vtable + 0x10 + N*8.
        # vfn at offset +0xe8 in vptr-space  =  raw addr ptr_addr + 0x8 + 0xe8
        # because vptr = vtable + 0x10, and slot at +0xe8 in vptr-space
        # is at vtable + 0x10 + 0xe8 = ptr_addr - 0x8 + 0x10 + 0xe8 = ptr_addr + 0xf0.
        slot_addr = ptr_addr + 0xf0
        try:
            slot_buf = bytearray(8)
            mem.getBytes(addr(slot_addr), slot_buf)
            slot_val = int.from_bytes(slot_buf, 'little')
            print('  typeinfo* found at 0x%x  -> vt[+0xe8] = 0x%016x  (fn @ 0x%016x)'
                  % (ptr_addr, slot_val, slot_val))
            # Dump that function.
            f = fm.getFunctionAt(addr(slot_val)) or fm.getFunctionContaining(addr(slot_val))
            if f:
                dump_fn(slot_val, 'stick3anet_vt_e8')
        except Exception as e:
            print('  err reading slot at 0x%x: %s' % (slot_addr, e))
        i = idx + 1

# Also try Stick3A typeinfo
print('\n--- searching for pointer 0x100C820F0 (Stick3A typeinfo) ---')
target2 = (0x100C820F0).to_bytes(8, 'little')
for block in mem.getBlocks():
    if not block.isInitialized() or block.isExecute(): continue
    size = block.getSize()
    if size > 64*1024*1024: continue
    bb = bytearray(size)
    try: block.getBytes(block.getStart(), bb)
    except: continue
    i = 0
    start = block.getStart().getOffset()
    while True:
        idx = bb.find(target2, i)
        if idx == -1: break
        ptr_addr = start + idx
        slot_addr = ptr_addr + 0xf0
        try:
            slot_buf = bytearray(8); mem.getBytes(addr(slot_addr), slot_buf)
            slot_val = int.from_bytes(slot_buf, 'little')
            print('  Stick3A typeinfo @ 0x%x -> vt[+0xe8] = 0x%016x' % (ptr_addr, slot_val))
            f = fm.getFunctionAt(addr(slot_val)) or fm.getFunctionContaining(addr(slot_val))
            if f:
                dump_fn(slot_val, 'stick3a_vt_e8')
        except Exception as e:
            print('  err: %s' % e)
        i = idx + 1

print('dump-vt-key-getter: done -> %s' % OUT)
